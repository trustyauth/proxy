package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/xsrftoken"
)

func TestCSRFMIddleware(t *testing.T) {
	// Mock next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	middleware := NewCSRF(nextHandler, "test-encryption-key-32-chars!", *logger)

	reqs := []struct {
		method string
		path   string
		body   io.Reader
	}{
		{"GET", "/test", nil},
		{"POST", "/test", nil},
		{"PUT", "/test", nil},
		{"DELETE", "/test", nil},
		{"PATCH", "/test", nil},
	}

	t.Run("Valid CSRF Token", func(t *testing.T) {
		for _, tt := range reqs {
			token := NewCSRFToken("test-encryption-key-32-chars!")

			req := httptest.NewRequest(tt.method, tt.path, tt.body)
			req.Header.Set(CSRFHeader, token.Token)
			req.AddCookie(&http.Cookie{Name: XSRFCookie, Value: token.Token})
			recorder := httptest.NewRecorder()

			middleware.ServeHTTP(recorder, req)

			resp := recorder.Result()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status code to be 200, got %d", resp.StatusCode)
			}

			assertValidCSRFResponse(t, resp)
		}
	})

	t.Run("Invalid CSRF Token", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", nil)
		req.Header.Set(CSRFHeader, "invalid-csrf-token")
		req.AddCookie(&http.Cookie{Name: XSRFCookie, Value: "test-csrf-token"})
		recorder := httptest.NewRecorder()

		middleware.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status code to be 403, got %d", resp.StatusCode)
		}
	})

	t.Run("Missing CSRF Header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", nil)
		req.AddCookie(&http.Cookie{Name: XSRFCookie, Value: "test-csrf-token"})
		recorder := httptest.NewRecorder()

		middleware.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status code to be 403, got %d", resp.StatusCode)
		}
	})

	t.Run("Missing CSRF Cookie", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", nil)
		req.Header.Set(CSRFHeader, "invalid-csrf-token")
		recorder := httptest.NewRecorder()

		middleware.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status code to be 403, got %d", resp.StatusCode)
		}
	})
}

func assertValidCSRFResponse(t *testing.T, resp *http.Response) {
	t.Helper()

	header := resp.Header.Get(CSRFHeader)
	if header == "" {
		t.Errorf("expected X-CSRF-TOKEN header to be set")
	}

	cookie := resp.Cookies()
	if len(cookie) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookie))
	}

	if cookie[0].Name != XSRFCookie {
		t.Errorf("expected cookie name to be %s, got %s", XSRFCookie, cookie[0].Name)
	}

	if cookie[0].Value == "" {
		t.Errorf("expected cookie value to be non-empty")
	}

	if cookie[0].Value != header {
		t.Errorf("expected XSRF-TOKEN cookie value to match X-CSRF-TOKEN header, want %s, got %s", header, cookie[0].Value)
	}
}

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
	key := "supersecretkey"
	csrfToken := NewCSRFToken(key)

	t.Run("Valid Token", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set(CSRFHeader, csrfToken.Token)
		req.AddCookie(&http.Cookie{Name: XSRFCookie, Value: csrfToken.Token})

		err := ValidateCSRFToken(req, key)
		if err != nil {
			t.Errorf("expected token to be valid, got error: %v", err)
		}
	})

	t.Run("Invalid Token", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set(CSRFHeader, "invalid-token")
		req.AddCookie(&http.Cookie{Name: XSRFCookie, Value: csrfToken.Token})

		err := ValidateCSRFToken(req, key)
		if err == nil {
			t.Errorf("expected token to be invalid")
		}
	})

	t.Run("Missing Header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		req.AddCookie(&http.Cookie{Name: XSRFCookie, Value: csrfToken.Token})

		err := ValidateCSRFToken(req, key)
		if err == nil {
			t.Errorf("expected error for missing header")
		}
	})

	t.Run("Missing Cookie", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set(CSRFHeader, csrfToken.Token)

		err := ValidateCSRFToken(req, key)
		if err == nil {
			t.Errorf("expected error for missing cookie")
		}
	})
}

func TestSetCookie(t *testing.T) {
	key := "supersecretkey"
	csrfToken := NewCSRFToken(key)

	recorder := httptest.NewRecorder()
	csrfToken.SetCookie(recorder)

	cookie := recorder.Result().Cookies()
	if len(cookie) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookie))
	}

	if cookie[0].Name != XSRFCookie {
		t.Errorf("expected cookie name to be %s, got %s", XSRFCookie, cookie[0].Name)
	}

	if cookie[0].Value != csrfToken.Token {
		t.Errorf("expected cookie value to be %s, got %s", csrfToken.Token, cookie[0].Value)
	}
}

func TestSetHeader(t *testing.T) {
	key := "supersecretkey"
	csrfToken := NewCSRFToken(key)

	recorder := httptest.NewRecorder()
	csrfToken.SetHeader(recorder)

	header := recorder.Header().Get(CSRFHeader)
	if header != csrfToken.Token {
		t.Errorf("expected header value to be %s, got %s", csrfToken.Token, header)
	}
}
