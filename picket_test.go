package picket

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"log/slog"
)

func TestReverseProxy_ServeHTTP(t *testing.T) {
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
	proxy := NewReverseProxy(originURL, "test-key", *slog.Default())

	// Create a request to the proxy
	req := httptest.NewRequest("GET", "/test", nil)
	recorder := httptest.NewRecorder()

	// Serve the request using the proxy
	proxy.ServeHTTP(recorder, req)

	// Check the response
	resp := recorder.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code to be 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "proxied response" {
		t.Errorf("expected body to be 'proxied response', got %s", string(body))
	}
}
