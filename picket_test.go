package picket

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"log/slog"

	"github.com/tjmcginnis/picket/crypto"
	"github.com/tjmcginnis/picket/middleware"
)

func TestNewReverseProxy(t *testing.T) {
	originURL, _ := url.Parse("http://example.com")
	testKey := "test-key-with-exactly-32-chars!!" // exactly 32 bytes
	proxy := NewReverseProxy(originURL, testKey, *slog.Default())

	if proxy.Origin.String() != "http://example.com" {
		t.Errorf("expected origin to be http://example.com, got %s", proxy.Origin.String())
	}

	if proxy.Mux == nil {
		t.Errorf("expected Mux to be non-nil")
	}
}

func TestReverseProxy_ServeHTTP(t *testing.T) {
	// Mock origin server
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/test" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied response"))
	}))
	defer originServer.Close()

	originURL, _ := url.Parse(originServer.URL)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	testKey := "test-key-with-exactly-32-chars!!" // exactly 32 bytes
	proxy := NewReverseProxy(originURL, testKey, *logger)

	t.Run("Valid Request", func(t *testing.T) {
		email := "test@example.com"
		encryptedEmail, _ := crypto.Encrypt(email, testKey)

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{Name: "picket", Value: encryptedEmail})
		recorder := httptest.NewRecorder()

		proxy.Mux.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status code to be 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "proxied response" {
			t.Errorf("expected body to be 'proxied response', got %s", string(body))
		}
	})

	t.Run("Invalid Path", func(t *testing.T) {
		email := "test@example.com"
		encryptedEmail, _ := crypto.Encrypt(email, testKey)

		req := httptest.NewRequest("GET", "/invalid", nil)
		req.AddCookie(&http.Cookie{Name: "picket", Value: encryptedEmail})
		recorder := httptest.NewRecorder()

		proxy.Mux.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected status code to be 404, got %d", resp.StatusCode)
		}
	})
}

func TestReverseProxy_WithMiddleware(t *testing.T) {
	// Mock origin server
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/test" {
			t.Errorf("expected path to be /test, got %s", r.URL.Path)
		}
		email := r.Header.Get(middleware.AuthHeader)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("proxied response for user: %s", email)))
	}))
	defer originServer.Close()

	originURL, _ := url.Parse(originServer.URL)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	testKey := "test-key-with-exactly-32-chars!!" // exactly 32 bytes
	proxy := NewReverseProxy(originURL, testKey, *logger)

	t.Run("Proxies Authenticated Request", func(t *testing.T) {
		email := "test@example.com"
		encryptedEmail, _ := crypto.Encrypt(email, testKey)
		csrfToken := middleware.NewCSRFToken(testKey)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(middleware.CSRFHeader, csrfToken.Token)
		req.AddCookie(&http.Cookie{Name: middleware.XSRFCookie, Value: csrfToken.Token})
		req.AddCookie(&http.Cookie{Name: "picket", Value: encryptedEmail})
		recorder := httptest.NewRecorder()

		proxy.Mux.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status code to be 200, got %d", resp.StatusCode)
		}

		cookie := resp.Cookies()
		if len(cookie) != 1 {
			t.Fatalf("expected 1 cookie, got %d", len(cookie))
		}

		if cookie[0].Name != middleware.XSRFCookie {
			t.Errorf("expected cookie name to be %s, got %s", middleware.XSRFCookie, cookie[0].Name)
		}

		if cookie[0].Value == "" {
			t.Errorf("expected cookie value to be non-empty")
		}

		if resp.Header.Get(middleware.CSRFHeader) == "" {
			t.Errorf("expected header to be non-empty")
		}

		if resp.Header.Get(middleware.CSRFHeader) != cookie[0].Value {
			t.Errorf("expected header to match cookie")
		}

		if resp.Header.Get(middleware.AuthHeader) != "" {
			t.Errorf("expected X-PICKET-USER-EMAIL to be excluded from response")
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "proxied response for user: "+email {
			t.Errorf("expected body to be 'proxied response for user: test@example.com', got %s", string(body))
		}
	})

	t.Run("Invalid CSRF Token with Valid Auth Cookie Should Not Set Email Header", func(t *testing.T) {
		email := "test@example.com"
		encryptedEmail, _ := crypto.Encrypt(email, testKey)

		req := httptest.NewRequest("POST", "/test", nil)
		req.AddCookie(&http.Cookie{Name: "picket", Value: encryptedEmail})
		req.Header.Set(middleware.CSRFHeader, "invalid-csrf-token")
		req.AddCookie(&http.Cookie{Name: middleware.XSRFCookie, Value: "invalid-csrf-cookie"})
		recorder := httptest.NewRecorder()

		proxy.Mux.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status code to be 403, got %d", resp.StatusCode)
		}
	})
}
