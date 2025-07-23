package nameshift

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
)

var (
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        5,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     90 * time.Second,
		},
	}
)

func tlsCertFromCertAndKeyPEMBundle(bundle []byte) (tls.Certificate, error) {
	certBuilder, keyBuilder := new(bytes.Buffer), new(bytes.Buffer)
	var foundKey bool // use only the first key in the file

	for {
		// Decode next block so we can see what type it is
		var derBlock *pem.Block
		derBlock, bundle = pem.Decode(bundle)
		if derBlock == nil {
			break
		}

		if derBlock.Type == "CERTIFICATE" {
			// Re-encode certificate as PEM, appending to certificate chain
			if err := pem.Encode(certBuilder, derBlock); err != nil {
				return tls.Certificate{}, err
			}
		} else if derBlock.Type == "EC PARAMETERS" {
			// EC keys generated from openssl can be composed of two blocks:
			// parameters and key (parameter block should come first)
			if !foundKey {
				// Encode parameters
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}

				// Key must immediately follow
				derBlock, bundle = pem.Decode(bundle)
				if derBlock == nil || derBlock.Type != "EC PRIVATE KEY" {
					return tls.Certificate{}, fmt.Errorf("expected elliptic private key to immediately follow EC parameters")
				}
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}
				foundKey = true
			}
		} else if derBlock.Type == "PRIVATE KEY" || strings.HasSuffix(derBlock.Type, " PRIVATE KEY") {
			// RSA key
			if !foundKey {
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}
				foundKey = true
			}
		} else {
			return tls.Certificate{}, fmt.Errorf("unrecognized PEM block type: %s", derBlock.Type)
		}
	}

	certPEMBytes, keyPEMBytes := certBuilder.Bytes(), keyBuilder.Bytes()
	if len(certPEMBytes) == 0 {
		return tls.Certificate{}, fmt.Errorf("failed to parse PEM data")
	}
	if len(keyPEMBytes) == 0 {
		return tls.Certificate{}, fmt.Errorf("no private key block found")
	}

	// if the start of the key file looks like an encrypted private key,
	// reject it with a helpful error message
	if strings.HasPrefix(string(keyPEMBytes[:40]), "ENCRYPTED") {
		return tls.Certificate{}, fmt.Errorf("encrypted private keys are not supported; please decrypt the key first")
	}

	cert, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("making X509 key pair: %v", err)
	}

	return cert, nil
}

func init() {
	caddy.RegisterModule(NameshiftCertGetter{})
}

type CertificateResponse struct {
	Id          string `json:"id"`
	Certificate string `json:"certificate"`
}

var (
	domainCertMapMutex sync.RWMutex
	domainCertMap      map[string]string

	certificatesMutex sync.RWMutex
	certificates      map[string]*tls.Certificate

	lastAccessMutex sync.RWMutex
	lastAccess      map[string]time.Time

	hasCertMutex sync.RWMutex
	hasCert      map[string]bool

	cleanupTicker *time.Ticker
)

// NameshiftCertGetter can get a certificate via HTTP(S) request.
type NameshiftCertGetter struct {
	// The URL from which to download the certificate. Required.
	//
	// The URL will be augmented with query string parameters taken
	// from the TLS handshake:
	//
	// - server_name: The SNI value
	//
	// To be valid, the response must be HTTP 200 with a PEM body
	// consisting of blocks for the certificate chain and the private
	// key.
	//
	// To indicate that this manager is not managing a certificate for
	// the described handshake, the endpoint should return HTTP 204
	// (No Content). Error statuses will indicate that the manager is
	// capable of providing a certificate but was unable to.
	URL        string `json:"url,omitempty"`
	LocalCache string `json:"local_cache,omitempty"`

	logger *zap.Logger
	ctx    context.Context
}

// CaddyModule returns the Caddy module information.
func (hcg NameshiftCertGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.nameshift",
		New: func() caddy.Module { return new(NameshiftCertGetter) },
	}
}

func (hcg *NameshiftCertGetter) Provision(ctx caddy.Context) error {
	hcg.ctx = ctx
	hcg.logger = ctx.Logger(hcg)
	domainCertMap = make(map[string]string)
	certificates = make(map[string]*tls.Certificate)
	lastAccess = make(map[string]time.Time)
	hasCert = make(map[string]bool)

	if hcg.URL == "" {
		return fmt.Errorf("URL is required")
	}

	// Start cleanup goroutine
	cleanupTicker = time.NewTicker(1 * time.Minute)
	go func() {
		for range cleanupTicker.C {
			certificatesMutex.Lock()
			lastAccessMutex.Lock()
			now := time.Now()
			// Only clear certificates that haven't been accessed in 5 minutes
			for id, lastUsed := range lastAccess {
				if now.Sub(lastUsed) > 5*time.Minute {
					delete(certificates, id)
					delete(lastAccess, id)
					hcg.logger.Debug(fmt.Sprintf("Cleared unused certificate from memory cache: %s", id))
				}
			}
			lastAccessMutex.Unlock()
			certificatesMutex.Unlock()
		}
	}()

	if hcg.LocalCache != "" {
		hcg.logger.Debug(fmt.Sprintf("Loading local certificates from cache: %s", hcg.LocalCache))

		files, err := os.ReadDir(hcg.LocalCache)
		if err != nil {
			os.MkdirAll(hcg.LocalCache, 0770)
			hcg.logger.Warn("Could not read local cache dir, creating...")
			return nil
		}

		// Only load domain mapping, not the actual certificates
		for _, file := range files {
			if !file.IsDir() {
				fullname := filepath.Join(hcg.LocalCache, file.Name())
				contents, err := os.ReadFile(fullname)
				if err != nil {
					log.Fatal(err)
				}

				cert, err := tlsCertFromCertAndKeyPEMBundle(contents)
				if err == nil {
					if time.Now().After(cert.Leaf.NotAfter) {
						hcg.logger.Debug(fmt.Sprintf("Certificate %s expired: %s", file.Name(), cert.Leaf.NotAfter))
						os.Remove(fullname)
						continue
					}

					// Only store the domain mapping, not the actual certificate
					domainCertMapMutex.Lock()
					for _, element := range cert.Leaf.DNSNames {
						domainCertMap[element] = file.Name()
					}
					domainCertMapMutex.Unlock()
				}
			}
		}
	}

	return nil
}

func (hcg NameshiftCertGetter) storeCertificateToDisk(id string, cert *[]byte) {
	os.WriteFile(
		filepath.Join(hcg.LocalCache, id),
		*cert,
		0644,
	)
}

func HasCertificate(name string) bool {
	hasCertMutex.RLock()
	defer hasCertMutex.RUnlock()

	return hasCert[name]
}

func (hcg NameshiftCertGetter) loadCertificateIntoMemoryCache(id string, cert *tls.Certificate) {
	certificatesMutex.Lock()
	lastAccessMutex.Lock()
	domainCertMapMutex.Lock()
	hasCertMutex.Lock()
	defer certificatesMutex.Unlock()
	defer lastAccessMutex.Unlock()
	defer domainCertMapMutex.Unlock()
	defer hasCertMutex.Unlock()

	// store in cache
	certificates[id] = cert
	lastAccess[id] = time.Now()

	hcg.logger.Debug(fmt.Sprintf("Storing certificate %s in cache. DNS Names: %s", id, cert.Leaf.DNSNames))

	// Update domain mapping and hasCert
	for _, element := range cert.Leaf.DNSNames {
		domainCertMap[element] = id
		hasCert[element] = true
	}
}

func (hcg NameshiftCertGetter) loadCertificateFromDisk(id string) (*tls.Certificate, error) {
	if hcg.LocalCache == "" {
		return nil, fmt.Errorf("no local cache configured")
	}

	fullname := filepath.Join(hcg.LocalCache, id)
	contents, err := os.ReadFile(fullname)
	if err != nil {
		return nil, err
	}

	cert, err := tlsCertFromCertAndKeyPEMBundle(contents)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

func (hcg NameshiftCertGetter) parseCertificateResponse(resp *http.Response) (*tls.Certificate, error) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var result CertificateResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %v", err)
	}

	if result.Certificate == "" {
		return nil, fmt.Errorf("empty certificate in response")
	}

	cert, err := tlsCertFromCertAndKeyPEMBundle([]byte(result.Certificate))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// is the cert still valid?
	if time.Now().Before(cert.Leaf.NotAfter) {
		certBytes := []byte(result.Certificate)
		hcg.loadCertificateIntoMemoryCache(result.Id, &cert)
		hcg.storeCertificateToDisk(result.Id, &certBytes)

		return &cert, nil
	}

	// we got an expired cert
	hcg.logger.Debug(fmt.Sprintf("Got an expired cert: %s", result.Id))

	return nil, fmt.Errorf("certificate is expired")
}

func (hcg NameshiftCertGetter) fetchCertificate(name string) (*tls.Certificate, error) {
	hcg.logger.Debug(fmt.Sprintf("Fetching certificate for %s.", name))

	if name == "" {
		return nil, fmt.Errorf("ignoring empty name")
	}

	// ignore ips
	if net.ParseIP(name) != nil {
		return nil, fmt.Errorf("ignoring %s, it is an IP", name)
	}

	parsed, err := url.Parse(hcg.URL)
	if err != nil {
		return nil, err
	}

	// parse domain into parts
	root, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimRight(name, "."))
	if err != nil {
		return nil, err
	}

	// is apex
	apex := root == name
	firstTwoCharacters := root[:2]

	// combine path to fetch certificate from
	path := fmt.Sprintf("/%s/%s/%s.json",
		map[bool]string{true: "apex", false: "www"}[apex],
		firstTwoCharacters,
		name)

	// try to fetch certificate directly from cache
	parsed.Path = path

	hcg.logger.Debug(fmt.Sprintf("Trying cdn cache url: %s", parsed.String()))
	req, err := http.NewRequestWithContext(hcg.ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from CDN: %v", err)
	}

	if resp.StatusCode == http.StatusOK {
		cert, err := hcg.parseCertificateResponse(resp)
		if err == nil && cert != nil {
			defer resp.Body.Close()

			return cert, nil
		}
	}

	// close body, we don't need it anymore - CANNOT be deferred
	resp.Body.Close()

	// try to fetch from API
	hcg.logger.Debug("Certificate not found in CDN, forcing fetch from origin API")

	parsed.Path = "/certificates/caddy"
	qs := parsed.Query()
	qs.Set("server_name", name)
	parsed.RawQuery = qs.Encode()

	hcg.logger.Debug(fmt.Sprintf("Fetching certificate from origin API: %s", parsed.String()))

	req, err = http.NewRequestWithContext(hcg.ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err = httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from API: %v", err)
	}

	if resp.StatusCode == http.StatusOK {
		cert, err := hcg.parseCertificateResponse(resp)
		if err == nil && cert != nil {
			defer resp.Body.Close()
			return cert, nil
		}
	}

	defer resp.Body.Close()

	return nil, fmt.Errorf("failed to fetch certificate from API")
}

func (hcg NameshiftCertGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// check if we have the certificate cached
	domainCertMapMutex.RLock()
	certificateId, ok := domainCertMap[hello.ServerName]
	domainCertMapMutex.RUnlock()

	if ok {
		hcg.logger.Debug(fmt.Sprintf("Found certificate mapping for %s. Certificate id: %s", hello.ServerName, certificateId))

		// Try to get from memory cache first
		certificatesMutex.RLock()
		cert := certificates[certificateId]
		certificatesMutex.RUnlock()

		if cert == nil {
			// not found in memory, try to load from disk
			hcg.logger.Debug(fmt.Sprintf("Certificate not found in memory, loading from disk: %s", certificateId))

			var err error
			cert, err = hcg.loadCertificateFromDisk(certificateId)
			if err == nil {
				hcg.loadCertificateIntoMemoryCache(certificateId, cert)
			}
		}

		if cert != nil {
			// Update last access time
			lastAccessMutex.Lock()
			lastAccess[certificateId] = time.Now()
			lastAccessMutex.Unlock()

			// check if expired
			if time.Now().After(cert.Leaf.NotAfter) {
				hcg.logger.Debug(fmt.Sprintf("Cached certificate for %s was expired, removing. Certificate id: %s", hello.ServerName, certificateId))
				certificatesMutex.Lock()
				lastAccessMutex.Lock()
				hasCertMutex.Lock()
				domainCertMapMutex.Lock()

				delete(certificates, certificateId)
				delete(lastAccess, certificateId)

				// Remove from hasCert map
				for _, element := range cert.Leaf.DNSNames {
					delete(hasCert, element)
					delete(domainCertMap, element)
				}

				certificatesMutex.Unlock()
				lastAccessMutex.Unlock()
				hasCertMutex.Unlock()
				domainCertMapMutex.Unlock()
			} else {
				// expires soon
				if time.Now().AddDate(0, 0, 5).After(cert.Leaf.NotAfter) {
					hcg.logger.Debug(fmt.Sprintf("Cached certificate for %s is expiring soon (%s), fetching new one. Certificate id: %s", hello.ServerName, cert.Leaf.NotAfter, certificateId))
					go hcg.fetchCertificate(hello.ServerName)
				}

				return cert, nil
			}
		}
	}

	return hcg.fetchCertificate(hello.ServerName)
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into ts.
//
//	... nameshift <url>
func (hcg *NameshiftCertGetter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume cert manager name

	if d.NextArg() {
		hcg.URL = d.Val()
	}

	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "local_cache":
			if !d.NextArg() {
				return d.ArgErr()
			}
			hcg.LocalCache = d.Val()
		case "url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			hcg.URL = d.Val()
		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
	}

	return nil
}

// Interface guards
var (
	_ certmagic.Manager     = (*NameshiftCertGetter)(nil)
	_ caddy.Provisioner     = (*NameshiftCertGetter)(nil)
	_ caddyfile.Unmarshaler = (*NameshiftCertGetter)(nil)
)
