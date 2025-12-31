package jwt

import gojwt "github.com/golang-jwt/jwt/v5"

// Claims defines the JWT claims structure.
type Claims struct {
	// HTU (HTTP Target URI) is the absolute HTTP/HTTPS URL where the user should be redirected.
	HTU string `json:"htu"`

	// RegisteredClaims embeds the standard JWT claims (exp, iat, nbf, sub, etc.).
	gojwt.RegisteredClaims
}
