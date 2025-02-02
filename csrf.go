package picket

import (
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

// ValidateCSRFToken validates a CSRF Token
func ValidateCSRFToken(token, key string) bool {
	return xsrftoken.Valid(token, key, "", "")
}
