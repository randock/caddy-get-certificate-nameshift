package nameshift

import (
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
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
	"golang.org/x/sync/singleflight"
)

const (
	maxCertificateCacheBytes int64 = 2 << 30
	negativeCacheTTL               = 30 * time.Second
	persistenceQueueSize           = 64
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

type certificateCacheEntry struct {
	id      string
	cert    *tls.Certificate
	size    int64
	element *list.Element
}

type certificateLRU struct {
	mutex    sync.Mutex
	entries  map[string]*certificateCacheEntry
	recency  *list.List
	maxBytes int64
	bytes    int64
}

func newCertificateLRU(maxBytes int64) *certificateLRU {
	return &certificateLRU{
		entries:  make(map[string]*certificateCacheEntry),
		recency:  list.New(),
		maxBytes: maxBytes,
	}
}

func (cache *certificateLRU) Get(id string) (*tls.Certificate, bool) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	entry, ok := cache.entries[id]
	if !ok {
		return nil, false
	}

	cache.recency.MoveToFront(entry.element)
	return entry.cert, true
}

func (cache *certificateLRU) Add(id string, cert *tls.Certificate, size int64) {
	if cert == nil || size <= 0 || size > cache.maxBytes {
		return
	}

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	if existing, ok := cache.entries[id]; ok {
		cache.bytes -= existing.size
		existing.cert = cert
		existing.size = size
		cache.bytes += size
		cache.recency.MoveToFront(existing.element)
	} else {
		entry := &certificateCacheEntry{id: id, cert: cert, size: size}
		entry.element = cache.recency.PushFront(entry)
		cache.entries[id] = entry
		cache.bytes += size
	}

	for cache.bytes > cache.maxBytes {
		oldestElement := cache.recency.Back()
		if oldestElement == nil {
			break
		}
		oldest := oldestElement.Value.(*certificateCacheEntry)
		delete(cache.entries, oldest.id)
		cache.recency.Remove(oldestElement)
		cache.bytes -= oldest.size
	}
}

func (cache *certificateLRU) Delete(id string) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	entry, ok := cache.entries[id]
	if !ok {
		return
	}

	delete(cache.entries, id)
	cache.recency.Remove(entry.element)
	cache.bytes -= entry.size
}

type certificatePersistence struct {
	id   string
	data []byte
}

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
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing leaf certificate: %v", err)
	}

	return cert, nil
}

func init() {
	caddy.RegisterModule(new(NameshiftCertGetter))
}

type CertificateResponse struct {
	Id          string `json:"id"`
	Certificate string `json:"certificate"`
}

var (
	domainCertMapMutex sync.RWMutex
	domainCertMap      map[string]string

	hasCertMutex sync.RWMutex
	hasCert      map[string]bool
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

	cache *certificateLRU

	fetchGroup singleflight.Group

	negativeCacheMutex sync.Mutex
	negativeCache      map[string]time.Time

	renewalMutex sync.Mutex
	renewals     map[string]bool

	persistenceQueue chan certificatePersistence
}

// CaddyModule returns the Caddy module information.
func (hcg *NameshiftCertGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.nameshift",
		New: func() caddy.Module { return new(NameshiftCertGetter) },
	}
}

func (hcg *NameshiftCertGetter) Provision(ctx caddy.Context) error {
	hcg.ctx = ctx
	hcg.logger = ctx.Logger(hcg)
	hcg.cache = newCertificateLRU(maxCertificateCacheBytes)
	hcg.negativeCache = make(map[string]time.Time)
	hcg.renewals = make(map[string]bool)

	domainCertMapMutex.Lock()
	domainCertMap = make(map[string]string)
	domainCertMapMutex.Unlock()
	hasCertMutex.Lock()
	hasCert = make(map[string]bool)
	hasCertMutex.Unlock()

	if hcg.URL == "" {
		return fmt.Errorf("URL is required")
	}

	if hcg.LocalCache != "" {
		hcg.logger.Debug("loading local certificates from cache", zap.String("path", hcg.LocalCache))

		if err := os.MkdirAll(hcg.LocalCache, 0700); err != nil {
			return fmt.Errorf("creating local certificate cache: %w", err)
		}

		files, err := os.ReadDir(hcg.LocalCache)
		if err != nil {
			return fmt.Errorf("reading local certificate cache: %w", err)
		}

		domainCertMapMutex.Lock()
		hasCertMutex.Lock()
		// Only load domain mapping, not the actual certificates
		for _, file := range files {
			if !file.IsDir() {
				fullname := filepath.Join(hcg.LocalCache, file.Name())
				contents, err := os.ReadFile(fullname)
				if err != nil {
					hcg.logger.Warn("could not read cached certificate", zap.String("path", fullname), zap.Error(err))
					continue
				}

				cert, err := tlsCertFromCertAndKeyPEMBundle(contents)
				if err == nil {
					if time.Now().After(cert.Leaf.NotAfter) {
						hcg.logger.Debug("cached certificate expired",
							zap.String("certificate_id", file.Name()),
							zap.Time("expired_at", cert.Leaf.NotAfter),
						)
						if err := os.Remove(fullname); err != nil {
							hcg.logger.Warn("could not remove expired cached certificate", zap.String("path", fullname), zap.Error(err))
						}
						continue
					}

					// Only store the domain mapping, not the actual certificate
					for _, element := range cert.Leaf.DNSNames {
						domainCertMap[element] = file.Name()
						hasCert[element] = true
					}
				} else {
					hcg.logger.Warn("could not parse cached certificate", zap.String("path", fullname), zap.Error(err))
				}
			}
		}
		hasCertMutex.Unlock()
		domainCertMapMutex.Unlock()

		hcg.persistenceQueue = make(chan certificatePersistence, persistenceQueueSize)
		go hcg.persistCertificates()
	}

	return nil
}

func (hcg *NameshiftCertGetter) persistCertificates() {
	for {
		select {
		case <-hcg.ctx.Done():
			return
		case persistence := <-hcg.persistenceQueue:
			if err := os.WriteFile(filepath.Join(hcg.LocalCache, persistence.id), persistence.data, 0600); err != nil {
				hcg.logger.Error("could not persist certificate", zap.String("certificate_id", persistence.id), zap.Error(err))
			}
		}
	}
}

func (hcg *NameshiftCertGetter) queueCertificatePersistence(id string, cert []byte) {
	if hcg.persistenceQueue == nil {
		return
	}

	select {
	case hcg.persistenceQueue <- certificatePersistence{id: id, data: cert}:
	default:
		hcg.logger.Warn("certificate persistence queue is full", zap.String("certificate_id", id))
	}
}

func HasCertificate(name string) bool {
	hasCertMutex.RLock()
	defer hasCertMutex.RUnlock()

	return hasCert[name]
}

func (hcg *NameshiftCertGetter) loadCertificateIntoMemoryCache(id string, cert *tls.Certificate, size int64) {
	hcg.cache.Add(id, cert, size)

	domainCertMapMutex.Lock()
	hasCertMutex.Lock()
	defer domainCertMapMutex.Unlock()
	defer hasCertMutex.Unlock()

	hcg.logger.Debug("storing certificate in memory cache",
		zap.String("certificate_id", id),
		zap.Strings("dns_names", cert.Leaf.DNSNames),
		zap.Time("expires_at", cert.Leaf.NotAfter),
	)

	// Update domain mapping and hasCert
	for _, element := range cert.Leaf.DNSNames {
		domainCertMap[element] = id
		hasCert[element] = true
	}
}

func (hcg *NameshiftCertGetter) loadCertificateFromDisk(id string) (*tls.Certificate, int64, error) {
	if hcg.LocalCache == "" {
		return nil, 0, fmt.Errorf("no local cache configured")
	}

	fullname := filepath.Join(hcg.LocalCache, id)
	contents, err := os.ReadFile(fullname)
	if err != nil {
		return nil, 0, err
	}

	cert, err := tlsCertFromCertAndKeyPEMBundle(contents)
	if err != nil {
		return nil, 0, err
	}

	return &cert, int64(len(contents)), nil
}

func (hcg *NameshiftCertGetter) parseCertificateResponse(resp *http.Response) (*tls.Certificate, error) {
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

	certBytes := []byte(result.Certificate)
	cert, err := tlsCertFromCertAndKeyPEMBundle(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// is the cert still valid?
	if time.Now().Before(cert.Leaf.NotAfter) {
		hcg.loadCertificateIntoMemoryCache(result.Id, &cert, int64(len(certBytes)))
		hcg.queueCertificatePersistence(result.Id, certBytes)

		return &cert, nil
	}

	// we got an expired cert
	hcg.logger.Debug("received expired certificate", zap.String("certificate_id", result.Id))

	return nil, fmt.Errorf("certificate is expired")
}

func (hcg *NameshiftCertGetter) isNegativeCached(name string) bool {
	hcg.negativeCacheMutex.Lock()
	defer hcg.negativeCacheMutex.Unlock()

	expiresAt, ok := hcg.negativeCache[name]
	if !ok {
		return false
	}
	if time.Now().After(expiresAt) {
		delete(hcg.negativeCache, name)
		return false
	}
	return true
}

func (hcg *NameshiftCertGetter) setNegativeCached(name string) {
	hcg.negativeCacheMutex.Lock()
	hcg.negativeCache[name] = time.Now().Add(negativeCacheTTL)
	hcg.negativeCacheMutex.Unlock()
}

func (hcg *NameshiftCertGetter) clearNegativeCached(name string) {
	hcg.negativeCacheMutex.Lock()
	delete(hcg.negativeCache, name)
	hcg.negativeCacheMutex.Unlock()
}

func (hcg *NameshiftCertGetter) fetchCertificate(name string) (*tls.Certificate, error) {
	if hcg.isNegativeCached(name) {
		return nil, fmt.Errorf("certificate fetch for %q is temporarily cached as failed", name)
	}

	value, err, _ := hcg.fetchGroup.Do(name, func() (any, error) {
		cert, fetchErr := hcg.fetchCertificateOnce(name)
		if fetchErr != nil {
			hcg.setNegativeCached(name)
			return nil, fetchErr
		}
		hcg.clearNegativeCached(name)
		return cert, nil
	})
	if err != nil {
		return nil, err
	}

	return value.(*tls.Certificate), nil
}

func (hcg *NameshiftCertGetter) fetchCertificateOnce(name string) (*tls.Certificate, error) {
	hcg.logger.Debug("fetching certificate", zap.String("server_name", name))

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

	// try to fetch from API
	hcg.logger.Debug("Fetching certificate from API")

	parsed.Path = "/certificates/caddy"
	qs := parsed.Query()
	qs.Set("server_name", name)
	parsed.RawQuery = qs.Encode()

	hcg.logger.Debug("fetching certificate from origin API", zap.String("server_name", name))

	req, err := http.NewRequestWithContext(hcg.ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		cert, err := hcg.parseCertificateResponse(resp)
		if err == nil && cert != nil {
			return cert, nil
		}
		if err != nil {
			return nil, err
		}
	}

	return nil, fmt.Errorf("failed to fetch certificate from API: HTTP %d", resp.StatusCode)
}

func (hcg *NameshiftCertGetter) refreshCertificateAsync(name string) {
	if hcg.isNegativeCached(name) {
		return
	}

	hcg.renewalMutex.Lock()
	if hcg.renewals[name] {
		hcg.renewalMutex.Unlock()
		return
	}
	hcg.renewals[name] = true
	hcg.renewalMutex.Unlock()

	go func() {
		defer func() {
			hcg.renewalMutex.Lock()
			delete(hcg.renewals, name)
			hcg.renewalMutex.Unlock()
		}()
		if _, err := hcg.fetchCertificate(name); err != nil {
			hcg.logger.Warn("background certificate refresh failed", zap.String("server_name", name), zap.Error(err))
		}
	}()
}

func (hcg *NameshiftCertGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// check if we have the certificate cached
	domainCertMapMutex.RLock()
	certificateId, ok := domainCertMap[hello.ServerName]
	domainCertMapMutex.RUnlock()

	if ok {
		hcg.logger.Debug("found certificate mapping",
			zap.String("server_name", hello.ServerName),
			zap.String("certificate_id", certificateId),
		)

		// Try to get from memory cache first
		cert, _ := hcg.cache.Get(certificateId)

		if cert == nil {
			// not found in memory, try to load from disk
			hcg.logger.Debug("certificate not found in memory; loading from disk", zap.String("certificate_id", certificateId))

			var err error
			var size int64
			cert, size, err = hcg.loadCertificateFromDisk(certificateId)
			if err == nil {
				hcg.loadCertificateIntoMemoryCache(certificateId, cert, size)
			}
		}

		if cert != nil {
			// check if expired
			if time.Now().After(cert.Leaf.NotAfter) {
				hcg.logger.Debug("cached certificate expired; removing",
					zap.String("server_name", hello.ServerName),
					zap.String("certificate_id", certificateId),
				)
				hcg.cache.Delete(certificateId)
				domainCertMapMutex.Lock()
				hasCertMutex.Lock()

				// Remove from hasCert map
				for _, element := range cert.Leaf.DNSNames {
					delete(hasCert, element)
					delete(domainCertMap, element)
				}

				domainCertMapMutex.Unlock()
				hasCertMutex.Unlock()
			} else {
				// expires soon
				if time.Now().AddDate(0, 0, 5).After(cert.Leaf.NotAfter) {
					hcg.logger.Debug("cached certificate is expiring soon; refreshing",
						zap.String("server_name", hello.ServerName),
						zap.String("certificate_id", certificateId),
						zap.Time("expires_at", cert.Leaf.NotAfter),
					)
					hcg.refreshCertificateAsync(hello.ServerName)
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
