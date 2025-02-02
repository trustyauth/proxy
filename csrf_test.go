package picket

import (
	"fmt"
	"testing"

	"golang.org/x/net/xsrftoken"
)

func TestNewCSRFToken(t *testing.T) {
	t.Run("NewCSRFToken", func(t *testing.T) {
		key := "supersecretkey"
		userID := "user123"
		method := "POST"
		path := "/submit"

		token := NewCSRFToken(key, userID, method, path)
		if token == nil {
			t.Fatal("expected token to be non-nil")
		}
		if token.Token == "" {
			t.Fatal("expected token to be non-empty")
		}

		action := fmt.Sprintf("%s %s", method, path)
		if !xsrftoken.Valid(token.Token, key, userID, action) {
			t.Fatal("expected token to be valid")
		}
	})
}
