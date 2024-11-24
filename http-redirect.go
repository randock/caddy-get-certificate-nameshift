package nameshift

import (
	"fmt"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})

	httpcaddyfile.RegisterHandlerDirective("redirect_if_cert_available", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("redirect_if_cert_available", httpcaddyfile.Before, "redir")
}

type Middleware struct {
	logger *zap.Logger
	tlsApp *caddytls.TLS
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.redirect_if_cert_available",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func (h *Middleware) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)

	tlsAppIface, err := ctx.AppIfConfigured("tls")
	if err != nil {
		return fmt.Errorf("getting tls app: %v", err)
	}

	h.tlsApp = tlsAppIface.(*caddytls.TLS)
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := &Middleware{}

	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return handler, err
}

func (h *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport // OK; probably had no port to begin with
	}
	return host
}

func (h *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	// start managing this host, we need a cert for it
	requestHost := hostOnly(r.Host)
	err := h.tlsApp.Manage([]string{requestHost})
	if err != nil {
		h.logger.Error(err.Error())
	}

	exists := HasCertificate(requestHost) || len(caddytls.AllMatchingCertificates(requestHost)) > 0
	h.logger.Debug(fmt.Sprintf("Checking certificate for %s: %t", r.Host, exists))

	if exists {
		h.logger.Debug(fmt.Sprintf("Certificate found for %s", r.Host))

		toURL := "https://"

		// since we redirect to the standard HTTPS port, we
		// do not need to include it in the redirect URL

		toURL += requestHost
		toURL += r.URL.RequestURI()

		// get rid of this disgusting unencrypted HTTP connection 🤢
		w.Header().Set("Connection", "close")

		http.Redirect(w, r, toURL, http.StatusMovedPermanently)
	} else {
		h.logger.Debug(fmt.Sprintf("No certificate found for %s", r.Host))
		return next.ServeHTTP(w, r)
	}

	return nil
}

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
)
