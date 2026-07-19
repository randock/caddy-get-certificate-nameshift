package nameshift

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func TestCertificateCacheSizeDefaultsTo256MiB(t *testing.T) {
	getter := &NameshiftCertGetter{}

	size, err := getter.cacheSizeLimit()
	if err != nil {
		t.Fatalf("getting default cache size: %v", err)
	}
	if size != 256<<20 {
		t.Fatalf("expected 256 MiB default cache, got %d bytes", size)
	}
}

func TestUnmarshalCaddyfileCertificateCacheSize(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`nameshift https://certificates.example {
		max_cache_size 2GB
	}`)
	getter := &NameshiftCertGetter{}

	if err := getter.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("unmarshalling Caddyfile: %v", err)
	}
	if getter.MaxCacheSize != 2_000_000_000 {
		t.Fatalf("expected 2 GB cache, got %d bytes", getter.MaxCacheSize)
	}
}

func TestUnmarshalCaddyfileRejectsInvalidCacheSize(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`nameshift https://certificates.example {
		max_cache_size enormous
	}`)
	getter := &NameshiftCertGetter{}

	if err := getter.UnmarshalCaddyfile(dispenser); err == nil {
		t.Fatal("expected invalid max_cache_size to fail")
	}
}

func TestCertificateLRUEvictsLeastRecentlyUsed(t *testing.T) {
	cache := newCertificateLRU(3)
	first := &tls.Certificate{}
	second := &tls.Certificate{}
	third := &tls.Certificate{}

	cache.Add("first", first, 2)
	cache.Add("second", second, 1)
	if _, ok := cache.Get("first"); !ok {
		t.Fatal("expected first certificate in cache")
	}
	cache.Add("third", third, 1)

	if _, ok := cache.Get("second"); ok {
		t.Fatal("expected least recently used certificate to be evicted")
	}
	if _, ok := cache.Get("first"); !ok {
		t.Fatal("expected recently used certificate to remain")
	}
	if _, ok := cache.Get("third"); !ok {
		t.Fatal("expected newly added certificate to remain")
	}
	if cache.bytes != 3 {
		t.Fatalf("expected 3 cached bytes, got %d", cache.bytes)
	}
}

func TestCertificateLRURejectsOversizedCertificate(t *testing.T) {
	cache := newCertificateLRU(1)
	certificate := &tls.Certificate{}

	cache.Add("oversized", certificate, 2)

	if _, ok := cache.Get("oversized"); ok {
		t.Fatal("expected oversized certificate not to be cached")
	}
}

func TestFetchCertificateUsesSingleflight(t *testing.T) {
	const domain = "example.test"
	bundle := certificateBundle(t, domain)
	var requests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		time.Sleep(50 * time.Millisecond)
		if err := json.NewEncoder(w).Encode(CertificateResponse{Id: "certificate-id", Certificate: string(bundle)}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
	defer server.Close()

	getter := newTestCertificateGetter(server.URL)
	const callers = 20
	start := make(chan struct{})
	errors := make(chan error, callers)
	var waitGroup sync.WaitGroup
	waitGroup.Add(callers)
	for range callers {
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := getter.fetchCertificate(domain)
			errors <- err
		}()
	}

	close(start)
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("fetching certificate: %v", err)
		}
	}

	if got := requests.Load(); got != 1 {
		t.Fatalf("expected one upstream request, got %d", got)
	}
}

func TestFetchCertificateNegativelyCachesFailures(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	getter := newTestCertificateGetter(server.URL)
	for range 2 {
		if _, err := getter.fetchCertificate("missing.test"); err == nil {
			t.Fatal("expected certificate fetch to fail")
		}
	}

	if got := requests.Load(); got != 1 {
		t.Fatalf("expected one upstream request during negative-cache TTL, got %d", got)
	}
}

func TestCertificatePersistenceRunsInBackground(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	getter := newTestCertificateGetter("https://example.test")
	getter.ctx = ctx
	getter.LocalCache = t.TempDir()
	getter.persistenceQueue = make(chan certificatePersistence, persistenceQueueSize)
	go getter.persistCertificates()

	getter.queueCertificatePersistence("certificate-id", []byte("certificate"))

	path := getter.LocalCache + "/certificate-id"
	deadline := time.Now().Add(time.Second)
	for {
		contents, err := os.ReadFile(path)
		if err == nil {
			if string(contents) != "certificate" {
				t.Fatalf("unexpected persisted contents %q", contents)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("certificate was not persisted: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newTestCertificateGetter(apiURL string) *NameshiftCertGetter {
	domainCertMapMutex.Lock()
	domainCertMap = make(map[string]string)
	domainCertMapMutex.Unlock()
	hasCertMutex.Lock()
	hasCert = make(map[string]bool)
	hasCertMutex.Unlock()

	return &NameshiftCertGetter{
		URL:           apiURL,
		logger:        zap.NewNop(),
		ctx:           context.Background(),
		cache:         newCertificateLRU(defaultMaxCertificateCacheBytes),
		negativeCache: make(map[string]time.Time),
		renewals:      make(map[string]bool),
	}
}

func certificateBundle(t *testing.T, domain string) []byte {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshalling private key: %v", err)
	}

	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER})...)
	return bundle
}
