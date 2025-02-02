package picket

import (
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/net/xsrftoken"
)

const (
	XSRFCookie = "XSRF-TOKEN"
	CSRFHeader = "X-CSRF-TOKEN"
)

// CSRFToken represents a cross-site request forgery token
type CSRFToken struct {
	Token string
}

// NewCSRFToken generates a new secure CSRF Token
func NewCSRFToken(key string) *CSRFToken {
	token := xsrftoken.Generate(key, "", "")
	return &CSRFToken{Token: token}
}

// SetCookie sets the CSRF Token in the response cookie
func (csrf *CSRFToken) SetCookie(w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     XSRFCookie,
		Value:    csrf.Token,
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
}

// SetHeader sets the CSRF Token in the response header
func (csrf *CSRFToken) SetHeader(w http.ResponseWriter) {
	w.Header().Set(CSRFHeader, csrf.Token)
}

// ValidateCSRFToken validates a CSRF Token
func ValidateCSRFToken(req *http.Request, key string) error {
	csrfHeader := req.Header.Get(CSRFHeader)

	if csrfHeader == "" {
		return fmt.Errorf("missing %s header", CSRFHeader)
	}

	csrfCookie, err := req.Cookie(XSRFCookie)
	if err != nil {
		return err
	}

	if csrfCookie == nil {
		return fmt.Errorf("missing %s cookie", XSRFCookie)
	}

	if csrfHeader != csrfCookie.Value {
		return errors.New("token mismatch")
	}

	if !xsrftoken.Valid(csrfCookie.Value, key, "", "") {
		return errors.New("invalid token")
	}

	return nil
}
