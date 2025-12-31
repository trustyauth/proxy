package jwt

import (
	"fmt"
	"net/mail"
	"net/url"
	"strings"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// Validator handles JWT validation.
type Validator struct {
	secret string
	domain string
}

// NewValidator creates a new JWT validator.
func NewValidator(secret, domain string) *Validator {
	return &Validator{
		secret: secret,
		domain: domain,
	}
}

// ValidateToken parses and validates a JWT token string.
// It returns the validated claims on success, or an error if validation fails.
func (v *Validator) ValidateToken(tokenString string) (*Claims, error) {
	token, err := gojwt.ParseWithClaims(tokenString, &Claims{}, func(token *gojwt.Token) (interface{}, error) {
		if token.Method != gojwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(v.secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if claims.HTU == "" {
		return nil, fmt.Errorf("missing htu claim")
	}

	htuURL, err := url.Parse(claims.HTU)
	if err != nil {
		return nil, fmt.Errorf("invalid htu URL: %w", err)
	}

	if normalizeHostname(htuURL.Hostname()) != normalizeHostname(v.domain) {
		return nil, fmt.Errorf("htu hostname %s does not match configured domain %s", htuURL.Hostname(), v.domain)
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("missing sub claim")
	}

	if !isValidEmail(claims.Subject) {
		return nil, fmt.Errorf("invalid email in sub claim: %s", claims.Subject)
	}

	return claims, nil
}

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// normalizeHostname converts a hostname to lowercase and removes any trailing dot.
// This ensures case-insensitive comparison per RFC 4343 and handles fully-qualified
// domain names that include the root dot.
func normalizeHostname(hostname string) string {
	return strings.ToLower(strings.TrimSuffix(hostname, "."))
}
