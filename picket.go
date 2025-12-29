package picket

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/tjmcginnis/picket/internal/middleware"
)

type ReverseProxy struct {
	origin *url.URL
	logger slog.Logger
	Mux    *http.ServeMux
}

// NewReverseProxy creates a new ReverseProxy
func NewReverseProxy(origin *url.URL, key string, logger slog.Logger) *ReverseProxy {
	rp := &ReverseProxy{
		origin: origin,
		logger: logger,
	}

	var handler http.Handler = rp
	handler = middleware.Auth(handler, key, logger)
	handler = middleware.CSRF(handler, key, logger)
	handler = middleware.Logging(handler, logger)

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	rp.Mux = mux

	return rp
}

// ServeHTTP proxies the request to the origin server
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
