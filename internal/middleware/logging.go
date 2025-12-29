package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// Logging returns a middleware handler that logs request details including timing and user info
func Logging(next http.Handler, logger slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		lrw := NewLoggingResponseWriter(w)
		next.ServeHTTP(lrw, r)

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

		logger.Info(r.URL.Path, logFields...)
	})
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
