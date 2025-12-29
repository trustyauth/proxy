package middleware

import (
	"log/slog"
	"net/http"
	"net/mail"

	"github.com/tjmcginnis/picket/internal/crypto"
)

const (
	// AuthHeader is the header used to pass the authenticated user's email
	AuthHeader = "X-PICKET-USER-EMAIL"
)

// Auth returns a middleware handler that validates authentication via encrypted cookie
func Auth(next http.Handler, key string, logger slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("picket")
		if err != nil || cookie == nil {
			logger.Error("picket cookie not found", "error", err, "path", r.URL.Path, "ip", r.RemoteAddr)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		decryptedValue, err := crypto.Decrypt(cookie.Value, key)
		if err != nil {
			logger.Error("failed to decrypt picket cookie", "error", err, "path", r.URL.Path, "ip", r.RemoteAddr)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if !isValidEmail(decryptedValue) {
			logger.Error("invalid email in picket cookie", "value", decryptedValue, "path", r.URL.Path, "ip", r.RemoteAddr)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		logger.Debug("valid picket cookie found", "email", decryptedValue, "path", r.URL.Path, "ip", r.RemoteAddr)
		r.Header.Set(AuthHeader, decryptedValue)
		next.ServeHTTP(w, r)
	})
}

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
