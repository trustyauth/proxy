package cookie

import "net/http"

const (
	Auth = "ta"
	XSRF = "XSRF-TOKEN"
)

// New creates a cookie with secure defaults: HttpOnly, Secure, SameSite=Lax, Path="/".
func New(name, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// WithDomain returns a copy of the cookie with the Domain field set.
func WithDomain(c *http.Cookie, domain string) *http.Cookie {
	c.Domain = domain
	return c
}
