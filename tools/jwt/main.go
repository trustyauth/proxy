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
	htu := flag.String("htu", "http://app.localhost:8888/dashboard", "Redirect URL for htu claim")
	domain := flag.String("domain", "app.localhost", "Domain to use in htu hostname")
	expireMinutes := flag.Int("expire", 5, "Token expiration in minutes (0 for expired token)")
	flag.Parse()

	// If domain is specified and doesn't match default, update htu to use the domain
	if *domain != "app.localhost" {
		*htu = fmt.Sprintf("http://%s", *domain)
	}

	var expiresAt *gojwt.NumericDate
	if *expireMinutes > 0 {
		expiresAt = gojwt.NewNumericDate(time.Now().Add(time.Duration(*expireMinutes) * time.Minute))
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
	fmt.Printf("http://app.localhost:8888/auth?token=%s\n", tokenString)
	fmt.Printf("\nExample curl command:\n")
	fmt.Printf("curl -v \"http://app.localhost:8888/auth?token=%s\"\n", tokenString)
}
