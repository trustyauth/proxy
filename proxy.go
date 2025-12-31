package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/trustyauth/proxy/internal/handlers"
	"github.com/trustyauth/proxy/internal/middleware"
)

// Config holds the configuration for the reverse proxy.
type Config struct {
	// Origin server to forward requests to.
	Origin string `yaml:"origin"`

	// Key for cookie encryption and XSRF tokens.
	Key string `yaml:"key"`

	// TASecret is the shared secret for JWT signature verification (HS256).
	TASecret string `yaml:"ta_secret"`

	// Domain is the allowed domain for hostname validation in JWT htu claim.
	Domain string `yaml:"domain"`
}

type ReverseProxy struct {
	origin *url.URL
	logger slog.Logger
	Mux    *http.ServeMux
}

// NewReverseProxy creates a new ReverseProxy.
func NewReverseProxy(config *Config, logger slog.Logger) (*ReverseProxy, error) {
	origin, err := url.Parse(config.Origin)
	if err != nil {
		return nil, err
	}
	rp := &ReverseProxy{
		origin: origin,
		logger: logger,
	}

	mux := http.NewServeMux()

	// Register /auth handler WITHOUT auth/CSRF middleware
	// Use "GET /auth" pattern to match only exact /auth requests
	var authHandler http.Handler = handlers.NewAuthHandler(config.TASecret, config.Key, config.Domain, logger)
	authHandler = middleware.Logging(authHandler, logger)
	mux.Handle("GET /auth", authHandler)

	// Create middleware chain for protected routes
	var handler http.Handler = rp
	handler = middleware.Auth(handler, config.Key, logger)
	handler = middleware.CSRF(handler, config.Key, logger)
	handler = middleware.Logging(handler, logger)
	mux.Handle("/", handler)

	rp.Mux = mux

	return rp, nil
}

// ServeHTTP proxies the request to the origin server.
func (rp ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Host = rp.origin.Host
	r.URL.Host = rp.origin.Host
	r.URL.Scheme = rp.origin.Scheme
	r.RequestURI = ""

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		rp.logger.Error("failed to proxy request to origin server", "error", err)
		return
	}

	status := resp.StatusCode

	w.WriteHeader(status)
	io.Copy(w, resp.Body)
}
