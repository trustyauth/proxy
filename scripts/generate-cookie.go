package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/tjmcginnis/picket/internal/crypto"
)

func main() {
	email := flag.String("email", "test@example.com", "Email address to encrypt in the cookie")
	key := flag.String("key", "test-encryption-key-is-full-length!", "Encryption key")
	flag.Parse()

	encrypted, err := crypto.Encrypt(*email, *key)
	if err != nil {
		log.Fatalf("Failed to encrypt email: %v", err)
	}

	fmt.Printf("Email: %s\n", *email)
	fmt.Printf("Encrypted cookie value: %s\n", encrypted)
	fmt.Printf("\nUsage with curl:\n")
	fmt.Printf("curl -H \"Cookie: picket=%s\" http://localhost:80\n", encrypted)
}
