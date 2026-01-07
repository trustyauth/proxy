package main

import (
	"flag"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	HTU string `json:"htu"`
	gojwt.RegisteredClaims
}

func main() {
	secret := flag.String("secret", "example-jwt-signing-secret-key-32b", "JWT signing secret")
	email := flag.String("email", "test@example.com", "User email for sub claim")
	htu := flag.String("htu", "", "Redirect URL for htu claim (auto-generated if empty)")
	domain := flag.String("domain", "app.localhost", "Domain to use in htu hostname")
	expireSeconds := flag.Int("expire", 60, "Token expiration in seconds (0 for expired token)")
	tls := flag.Bool("tls", false, "Use HTTPS scheme and port 443")
	flag.Parse()

	// Set scheme, port, and curl flags based on TLS mode
	scheme := "http"
	port := "8888"
	curlFlags := "-v"
	if *tls {
		scheme = "https"
		port = "443"
		curlFlags = "-vk"
	}
	baseURL := fmt.Sprintf("%s://%s:%s", scheme, *domain, port)

	// Generate htu if not specified
	if *htu == "" {
		*htu = fmt.Sprintf("%s/dashboard", baseURL)
	}

	var expiresAt *gojwt.NumericDate
	if *expireSeconds > 0 {
		expiresAt = gojwt.NewNumericDate(time.Now().Add(time.Duration(*expireSeconds) * time.Second))
	} else {
		// Create expired token (1 hour in the past)
		expiresAt = gojwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
	}

	claims := &Claims{
		HTU: *htu,
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject:   *email,
			ExpiresAt: expiresAt,
			IssuedAt:  gojwt.NewNumericDate(time.Now()),
			NotBefore: gojwt.NewNumericDate(time.Now()),
		},
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(*secret))
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}

	fmt.Println("JWT Token Generated:")
	fmt.Println("---")
	fmt.Printf("Secret: %s\n", *secret)
	fmt.Printf("Email:  %s\n", *email)
	fmt.Printf("HTU:    %s\n", *htu)
	fmt.Printf("Expires: %s\n", expiresAt.Time.Format(time.RFC3339))
	fmt.Println("---")
	fmt.Println(tokenString)
	fmt.Println("---")
	fmt.Printf("\nTest URL:\n")
	fmt.Printf("%s/auth?token=%s\n", baseURL, tokenString)
	fmt.Printf("\nExample curl command:\n")
	fmt.Printf("curl %s \"%s/auth?token=%s\"\n", curlFlags, baseURL, tokenString)
}
