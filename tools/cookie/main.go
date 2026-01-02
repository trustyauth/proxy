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
	flag.Parse()

	encrypted, err := crypto.Encrypt(*email, *key)
	if err != nil {
		log.Fatalf("Failed to encrypt email: %v", err)
	}

	csrfToken := xsrftoken.Generate(*key, "", "")

	fmt.Printf("Email: %s\n", *email)
	fmt.Printf("Encrypted cookie value: %s\n", encrypted)
	fmt.Printf("CSRF token: %s\n", csrfToken)
	fmt.Printf("\nGET request:\n")
	fmt.Printf("curl -H \"Cookie: %s=%s\" http://app.localhost:8888\n", cookie.Auth, encrypted)
	fmt.Printf("\nPOST request:\n")
	fmt.Printf("curl -X POST -H \"Cookie: %s=%s; %s=%s\" -H \"X-CSRF-TOKEN: %s\" http://app.localhost:8888\n",
		cookie.Auth, encrypted, cookie.XSRF, csrfToken, csrfToken)
}
