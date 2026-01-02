package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"golang.org/x/net/xsrftoken"

	"github.com/trustyauth/proxy/internal/cookie"
)

// CSRF returns a middleware handler that validates CSRF tokens for state-changing requests
func CSRF(next http.Handler, key string, logger slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldProtect(r) {
			err := ValidateCSRFToken(r, key)
			if err != nil {
				logger.Error("failed to validate csrf", "error", err)
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		csrf := NewCSRFToken(key)
		csrf.SetCookie(w)
		csrf.SetHeader(w)

		next.ServeHTTP(w, r)
	})
}

const CSRFHeader = "X-CSRF-TOKEN"

type CSRFToken struct {
	Token string
}

func NewCSRFToken(key string) *CSRFToken {
	token := xsrftoken.Generate(key, "", "")
	return &CSRFToken{Token: token}
}

func (csrf *CSRFToken) SetCookie(w http.ResponseWriter) {
	http.SetCookie(w, cookie.New(cookie.XSRF, csrf.Token))
}

func (csrf *CSRFToken) SetHeader(w http.ResponseWriter) {
	w.Header().Set(CSRFHeader, csrf.Token)
}

func ValidateCSRFToken(req *http.Request, key string) error {
	csrfHeader := req.Header.Get(CSRFHeader)

	if csrfHeader == "" {
		return fmt.Errorf("missing %s header", CSRFHeader)
	}

	csrfCookie, err := req.Cookie(cookie.XSRF)
	if err != nil {
		return err
	}

	if csrfCookie == nil {
		return fmt.Errorf("missing %s cookie", cookie.XSRF)
	}

	if csrfHeader != csrfCookie.Value {
		return errors.New("token mismatch")
	}

	if !xsrftoken.Valid(csrfCookie.Value, key, "", "") {
		return errors.New("invalid token")
	}

	return nil
}

func shouldProtect(r *http.Request) bool {
	return r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete
}
