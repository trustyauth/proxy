package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const MinKeyLength = 32 // Minimum key length for AES-256

// Encrypt encrypts plaintext using AES-GCM with the provided key
func Encrypt(plaintext, key string) (string, error) {
	keyBytes, err := prepareKey(key)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-GCM with the provided key
func Decrypt(ciphertext, key string) (string, error) {
	keyBytes, err := prepareKey(key)
	if err != nil {
		return "", err
	}

	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext_bytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext_bytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// prepareKey validates and prepares the key for AES-256
func prepareKey(key string) ([]byte, error) {
	keyBytes := []byte(key)
	keyLen := len(keyBytes)

	if keyLen < MinKeyLength {
		return nil, fmt.Errorf("encryption key must be at least %d bytes", MinKeyLength)
	}

	// Truncate if longer than 32 bytes
	if keyLen > MinKeyLength {
		return keyBytes[:MinKeyLength], nil
	}

	return keyBytes, nil
}
