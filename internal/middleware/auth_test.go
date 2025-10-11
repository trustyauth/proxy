package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tjmcginnis/picket/internal/crypto"
)

func TestAuthMiddleware(t *testing.T) {
	// Mock next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	testKey := "test-encryption-key-32-chars!!!!" // exactly 32 bytes
	middleware := NewAuth(nextHandler, testKey, *logger)

	t.Run("Valid Email Cookie", func(t *testing.T) {
		email := "test@example.com"
		encryptedEmail, err := crypto.Encrypt(email, testKey)
		if err != nil {
			t.Fatalf("failed to encrypt email: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{Name: "picket", Value: encryptedEmail})
		recorder := httptest.NewRecorder()

		middleware.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status code to be 200, got %d", resp.StatusCode)
		}

		emailHeader := req.Header.Get(AuthHeader)
		if emailHeader != email {
			t.Errorf("expected X-PICKET-USER-EMAIL header to be %s, got %s", email, emailHeader)
		}
	})

	t.Run("Invalid Email Cookie", func(t *testing.T) {
		invalidEmail := "not-an-email"
		encryptedInvalid, err := crypto.Encrypt(invalidEmail, testKey)
		if err != nil {
			t.Fatalf("failed to encrypt invalid email: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{Name: "picket", Value: encryptedInvalid})
		recorder := httptest.NewRecorder()

		middleware.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status code to be 403, got %d", resp.StatusCode)
		}

		emailHeader := req.Header.Get(AuthHeader)
		if emailHeader != "" {
			t.Errorf("expected X-PICKET-USER-EMAIL header to be empty, got %s", emailHeader)
		}
	})

	t.Run("No Picket Cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		middleware.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status code to be 403, got %d", resp.StatusCode)
		}

		emailHeader := req.Header.Get(AuthHeader)
		if emailHeader != "" {
			t.Errorf("expected X-PICKET-USER-EMAIL header to be empty, got %s", emailHeader)
		}
	})

	t.Run("Invalid Encrypted Cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{Name: "picket", Value: "invalid-encrypted-data"})
		recorder := httptest.NewRecorder()

		middleware.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status code to be 403, got %d", resp.StatusCode)
		}

		emailHeader := req.Header.Get(AuthHeader)
		if emailHeader != "" {
			t.Errorf("expected X-PICKET-USER-EMAIL header to be empty, got %s", emailHeader)
		}
	})
}
