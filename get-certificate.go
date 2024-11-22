package httpredirect

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
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

	logger        *zap.Logger
	ctx           context.Context
	domainCertMap map[string]string
	certificates  map[string]tls.Certificate
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
	hcg.domainCertMap = make(map[string]string)
	hcg.certificates = make(map[string]tls.Certificate)

	if hcg.URL == "" {
		return fmt.Errorf("URL is required")
	}

	if hcg.LocalCache != "" {
		hcg.logger.Debug(fmt.Sprintf("Loading local certificates from cache: %s", hcg.LocalCache))

		files, err := os.ReadDir(hcg.LocalCache)
		if err != nil {
			log.Fatal(err)
		}

		for _, file := range files {
			if !file.IsDir() {
				// grab contents
				hcg.logger.Debug(fmt.Sprintf("Loading certificate %s from disk", file.Name()))

				fullname := filepath.Join(hcg.LocalCache, file.Name())
				contents, err := os.ReadFile(fullname)
				if err != nil {
					log.Fatal(err)
				}

				// see if it's valid cert
				cert, err := tlsCertFromCertAndKeyPEMBundle(contents)
				if err == nil {
					if time.Now().After(cert.Leaf.NotAfter) {
						hcg.logger.Debug(fmt.Sprintf("Certificate %s expired: %s", file.Name(), cert.Leaf.NotAfter))
						os.Remove(fullname)
						continue
					}

					hcg.loadCertificateIntoMemoryCache(file.Name(), cert)
				}
			}
		}
	}

	return nil
}

func (hcg NameshiftCertGetter) storeCertificateToDisk(id string, cert []byte) {
	os.WriteFile(
		filepath.Join(hcg.LocalCache, id),
		cert,
		0644,
	)
}

func (hcg NameshiftCertGetter) loadCertificateIntoMemoryCache(id string, cert tls.Certificate) {
	// store in cache
	hcg.certificates[id] = cert

	hcg.logger.Debug(fmt.Sprintf("Storing certificate %s in cache. DNS Names: %s", id, cert.Leaf.DNSNames))

	for _, element := range cert.Leaf.DNSNames {
		hcg.domainCertMap[element] = id
	}
}

func (hcg NameshiftCertGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {

	// check if we have the certificate cached
	certificateId, ok := hcg.domainCertMap[hello.ServerName]
	if ok {
		hcg.logger.Debug(fmt.Sprintf("Cached certificate found for %s. Certificate id: %s", hello.ServerName, certificateId))

		cert := hcg.certificates[certificateId]
		return &cert, nil
	}

	hcg.logger.Debug(fmt.Sprintf("No cached certificate found for %s. Fetching from API.", hello.ServerName))

	parsed, err := url.Parse(hcg.URL)
	if err != nil {
		return nil, err
	}

	qs := parsed.Query()
	qs.Set("server_name", hello.ServerName)
	parsed.RawQuery = qs.Encode()

	req, err := http.NewRequestWithContext(hcg.ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		// endpoint is not managing certs for this handshake
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got HTTP %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var result CertificateResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	pem := []byte(result.Certificate)

	cert, err := tlsCertFromCertAndKeyPEMBundle(pem)
	if err != nil {
		return nil, err
	}

	hcg.loadCertificateIntoMemoryCache(result.Id, cert)
	hcg.storeCertificateToDisk(result.Id, pem)

	return &cert, nil
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