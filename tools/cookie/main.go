package main

import (
	"flag"
	"fmt"
	"log"

	"golang.org/x/net/xsrftoken"

	"github.com/trustyauth/proxy/internal/cookie"
	"github.com/trustyauth/proxy/internal/crypto"
)

func main() {
	email := flag.String("email", "test@example.com", "Email address to encrypt in the cookie")
	key := flag.String("key", "test-encryption-key-is-full-length!", "Encryption key")
	tls := flag.Bool("tls", false, "Use HTTPS scheme and port 443")
	flag.Parse()

	encrypted, err := crypto.Encrypt(*email, *key)
	if err != nil {
		log.Fatalf("Failed to encrypt email: %v", err)
	}

	csrfToken := xsrftoken.Generate(*key, "", "")

	// Set scheme, port, and curl flags based on TLS mode
	scheme := "http"
	port := "8888"
	curlFlags := ""
	if *tls {
		scheme = "https"
		port = "443"
		curlFlags = "-k "
	}
	baseURL := fmt.Sprintf("%s://app.localhost:%s", scheme, port)

	fmt.Printf("Email: %s\n", *email)
	fmt.Printf("Encrypted cookie value: %s\n", encrypted)
	fmt.Printf("CSRF token: %s\n", csrfToken)
	fmt.Printf("\nGET request:\n")
	fmt.Printf("curl %s-H \"Cookie: %s=%s\" %s\n", curlFlags, cookie.Auth, encrypted, baseURL)
	fmt.Printf("\nPOST request:\n")
	fmt.Printf("curl %s-X POST -H \"Cookie: %s=%s; %s=%s\" -H \"X-CSRF-TOKEN: %s\" %s\n",
		curlFlags, cookie.Auth, encrypted, cookie.XSRF, csrfToken, csrfToken, baseURL)
}
