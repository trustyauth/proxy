package picket

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"log/slog"
)

func TestNewReverseProxy(t *testing.T) {
	originURL, _ := url.Parse("http://example.com")
	proxy := NewReverseProxy(originURL, "test-key", *slog.Default())

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
	proxy := NewReverseProxy(originURL, "test-key", *logger)

	t.Run("Valid Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
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
		req := httptest.NewRequest("GET", "/invalid", nil)
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
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied response"))
	}))
	defer originServer.Close()

	originURL, _ := url.Parse(originServer.URL)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewReverseProxy(originURL, "test-key", *logger)

	t.Run("Adds CSRF Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
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

		if cookie[0].Name != XSRFCookie {
			t.Errorf("expected cookie name to be %s, got %s", XSRFCookie, cookie[0].Name)
		}

		if cookie[0].Value == "" {
			t.Errorf("expected cookie value to be non-empty")
		}

		if resp.Header.Get(CSRFHeader) == "" {
			t.Errorf("expected header to be non-empty")
		}

		if resp.Header.Get(CSRFHeader) != cookie[0].Value {
			t.Errorf("expected header to match cookie")
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "proxied response" {
			t.Errorf("expected body to be 'proxied response', got %s", string(body))
		}
	})

	t.Run("Valid CSRF Token", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", nil)
		csrfToken := NewCSRFToken("test-key")
		req.Header.Set(CSRFHeader, csrfToken.Token)
		req.AddCookie(&http.Cookie{Name: XSRFCookie, Value: csrfToken.Token})
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

	t.Run("Invalid CSRF Token", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", nil)
		req.Header.Set(CSRFHeader, "invalid-csrf-token")
		req.AddCookie(&http.Cookie{Name: XSRFCookie, Value: "test-csrf-token"})
		recorder := httptest.NewRecorder()

		proxy.Mux.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status code to be 403, got %d", resp.StatusCode)
		}
	})
}
