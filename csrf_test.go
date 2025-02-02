package picket

import (
	"net/http"
	"net/http/httptest"
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
