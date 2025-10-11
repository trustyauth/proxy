package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

type Logging struct {
	next http.Handler
	slog.Logger
}

func NewLogging(next http.Handler, logger slog.Logger) *Logging {
	return &Logging{
		next:   next,
		Logger: logger,
	}
}

func (lm *Logging) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	lrw := NewLoggingResponseWriter(w)
	lm.next.ServeHTTP(lrw, r)

	end := time.Now()

	// Capture user email if set by auth middleware
	email := r.Header.Get(AuthHeader)

	logFields := []any{
		"ip", r.RemoteAddr,
		"method", r.Method,
		"protocol", r.Proto,
		"status", lrw.statusCode,
		"ua", r.UserAgent(),
		"duration", end.Sub(start),
	}

	// Add email field if present
	if email != "" {
		logFields = append(logFields, "user", email)
	}

	lm.Logger.Info(r.URL.Path, logFields...)
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
