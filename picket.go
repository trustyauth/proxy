package picket

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

type ReverseProxy struct {
	Origin *url.URL
	Logger slog.Logger
	Mux    *http.ServeMux
}

// NewReverseProxy creates a new ReverseProxy
func NewReverseProxy(origin *url.URL, key string, logger slog.Logger) *ReverseProxy {
	rp := &ReverseProxy{
		Origin: origin,
		Logger: logger,
	}

	csrf := csrfMiddleware{*rp, key, logger}
	logging := loggingMiddleware{csrf, logger}

	mux := http.NewServeMux()
	mux.Handle("/", logging)

	rp.Mux = mux

	return rp
}

// ServeHTTP proxies the request to the origin server
func (rp ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Host = rp.Origin.Host
	r.URL.Host = rp.Origin.Host
	r.URL.Scheme = rp.Origin.Scheme
	r.RequestURI = ""

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		rp.Logger.Error("failed to proxy request to origin server", "error", err)
		return
	}

	status := resp.StatusCode

	w.WriteHeader(status)
	io.Copy(w, resp.Body)
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK}
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

type loggingMiddleware struct {
	next http.Handler
	slog.Logger
}

func (lm loggingMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	lrw := NewLoggingResponseWriter(w)
	lm.next.ServeHTTP(lrw, r)

	end := time.Now()
	lm.Logger.Info(r.URL.Path,
		"ip", r.RemoteAddr,
		"method", r.Method,
		"protocol", r.Proto,
		"status", lrw.statusCode,
		"ua", r.UserAgent(),
		"duration", end.Sub(start),
	)
}

type csrfMiddleware struct {
	next http.Handler
	key  string
	slog.Logger
}

func (cm csrfMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if shouldProtect(r) {
		err := ValidateCSRFToken(r, cm.key)
		if err != nil {
			cm.Logger.Error("failed to validate csrf", "error", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
	} else {
		csrf := NewCSRFToken(cm.key)
		csrf.SetCookie(w)
		csrf.SetHeader(w)
	}

	cm.next.ServeHTTP(w, r)
}
