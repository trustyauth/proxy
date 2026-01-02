package middleware

import (
	"log/slog"
	"net/http"

	"github.com/trustyauth/proxy/internal/cookie"
	"github.com/trustyauth/proxy/internal/crypto"
	"github.com/trustyauth/proxy/internal/email"
)

const (
	// AuthHeader is the header used to pass the authenticated user's email
	AuthHeader = "X-TA-USER-EMAIL"
)

// Auth returns a middleware handler that validates authentication via encrypted cookie
func Auth(next http.Handler, key string, logger slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookie.Auth)
		if err != nil || c == nil {
			logger.Error("ta cookie not found", "error", err, "path", r.URL.Path, "ip", r.RemoteAddr)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		decryptedValue, err := crypto.Decrypt(c.Value, key)
		if err != nil {
			logger.Error("failed to decrypt ta cookie", "error", err, "path", r.URL.Path, "ip", r.RemoteAddr)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if !email.IsValid(decryptedValue) {
			logger.Error("invalid email in ta cookie", "value", decryptedValue, "path", r.URL.Path, "ip", r.RemoteAddr)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		logger.Debug("valid ta cookie found", "email", decryptedValue, "path", r.URL.Path, "ip", r.RemoteAddr)
		r.Header.Set(AuthHeader, decryptedValue)
		next.ServeHTTP(w, r)
	})
}
