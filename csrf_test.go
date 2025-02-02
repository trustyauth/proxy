package picket

import (
	"testing"

	"golang.org/x/net/xsrftoken"
)

func TestNewCSRFToken(t *testing.T) {
	t.Run("NewCSRFToken", func(t *testing.T) {
		key := "supersecretkey"

		token := NewCSRFToken(key)
		if token == nil {
			t.Fatal("expected token to be non-nil")
		}
		if token.Token == "" {
			t.Fatal("expected token to be non-empty")
		}

		if !xsrftoken.Valid(token.Token, key, "", "") {
			t.Fatal("expected token to be valid")
		}
	})
}

func TestValidateCSRFToken(t *testing.T) {
	key := "test-key"
	csrfToken := NewCSRFToken(key)

	if !ValidateCSRFToken(csrfToken.Token, key) {
		t.Errorf("expected token to be valid")
	}

	invalidKey := "invalid-key"
	if ValidateCSRFToken(csrfToken.Token, invalidKey) {
		t.Errorf("expected token to be invalid with a different key")
	}
}
