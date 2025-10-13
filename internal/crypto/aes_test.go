package crypto

import "testing"

func TestEncryptDecrypt(t *testing.T) {
	key := "test-encryption-key-32-chars!!!!" // exactly 32 bytes
	plaintext := "test@example.com"

	t.Run("Encrypt and Decrypt", func(t *testing.T) {
		encrypted, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("failed to encrypt: %v", err)
		}

		if encrypted == "" {
			t.Error("expected encrypted text to be non-empty")
		}

		decrypted, err := Decrypt(encrypted, key)
		if err != nil {
			t.Fatalf("failed to decrypt: %v", err)
		}

		if decrypted != plaintext {
			t.Errorf("expected decrypted text to be %s, got %s", plaintext, decrypted)
		}
	})

	t.Run("Invalid Encrypted Data", func(t *testing.T) {
		_, err := Decrypt("invalid-data", key)
		if err == nil {
			t.Error("expected error for invalid encrypted data")
		}
	})

	t.Run("Different Keys", func(t *testing.T) {
		encrypted, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("failed to encrypt: %v", err)
		}

		// Try to decrypt with different key (but valid length)
		differentKey := "different-key-32-chars-exactly!!"
		_, err = Decrypt(encrypted, differentKey)
		if err == nil {
			t.Error("expected error when decrypting with different key")
		}
	})

	t.Run("Empty Plaintext", func(t *testing.T) {
		encrypted, err := Encrypt("", key)
		if err != nil {
			t.Fatalf("failed to encrypt empty string: %v", err)
		}

		decrypted, err := Decrypt(encrypted, key)
		if err != nil {
			t.Fatalf("failed to decrypt empty string: %v", err)
		}

		if decrypted != "" {
			t.Errorf("expected empty string, got %s", decrypted)
		}
	})

	t.Run("Short Key Error", func(t *testing.T) {
		shortKey := "short"
		_, err := Encrypt(plaintext, shortKey)
		if err == nil {
			t.Error("expected error for short key")
		}
		if err.Error() != "encryption key must be at least 32 bytes" {
			t.Errorf("unexpected error message: %v", err)
		}

		// Also test decrypt with short key
		_, err = Decrypt("dummy", shortKey)
		if err == nil {
			t.Error("expected error for short key in decrypt")
		}
	})

	t.Run("Key Truncation", func(t *testing.T) {
		// Test that keys longer than 32 bytes are truncated
		longKey := "this-is-a-very-long-key-that-is-more-than-32-bytes"
		truncatedKey := longKey[:MinKeyLength]

		encrypted1, err := Encrypt(plaintext, longKey)
		if err != nil {
			t.Fatalf("failed to encrypt with long key: %v", err)
		}

		// Decrypt with truncated key should work
		decrypted1, err := Decrypt(encrypted1, truncatedKey)
		if err != nil {
			t.Fatalf("failed to decrypt: %v", err)
		}
		if decrypted1 != plaintext {
			t.Error("decryption failed with truncated key")
		}
	})
}
