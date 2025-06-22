package crypto

import "testing"

func TestEncryptDecrypt(t *testing.T) {
	key := "test-encryption-key-32-chars!"
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

		// Try to decrypt with different key
		_, err = Decrypt(encrypted, "different-key")
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
}
