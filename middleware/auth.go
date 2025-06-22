package middleware

import (
	"log/slog"
	"net/http"
	"net/mail"

	"github.com/tjmcginnis/picket/crypto"
)

type Auth struct {
	next http.Handler
	key  string
	slog.Logger
}

const (
	// AuthHeader is the header used to pass the authenticated user's email
	AuthHeader = "X-PICKET-USER-EMAIL"
)

func NewAuth(next http.Handler, key string, logger slog.Logger) *Auth {
	return &Auth{
		next:   next,
		key:    key,
		Logger: logger,
	}
}

func (am *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("picket")
	if err != nil || cookie == nil {
		am.Logger.Error("picket cookie not found", "error", err, "path", r.URL.Path, "ip", r.RemoteAddr)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	decryptedValue, err := crypto.Decrypt(cookie.Value, am.key)
	if err != nil {
		am.Logger.Error("failed to decrypt picket cookie", "error", err, "path", r.URL.Path, "ip", r.RemoteAddr)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if !isValidEmail(decryptedValue) {
		am.Logger.Error("invalid email in picket cookie", "value", decryptedValue, "path", r.URL.Path, "ip", r.RemoteAddr)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	am.Logger.Debug("valid picket cookie found", "email", decryptedValue, "path", r.URL.Path, "ip", r.RemoteAddr)
	r.Header.Set(AuthHeader, decryptedValue)
	am.next.ServeHTTP(w, r)
}

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
