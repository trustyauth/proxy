package picket

import (
	"fmt"

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
func NewCSRFToken(key, userID, method, path string) *CSRFToken {
	action := fmt.Sprintf("%s %s", method, path)
	token := xsrftoken.Generate(key, userID, action)
	return &CSRFToken{Token: token}
}
