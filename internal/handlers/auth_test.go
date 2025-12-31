package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/trustyauth/proxy/internal/crypto"
	internalJWT "github.com/trustyauth/proxy/internal/jwt"
)

const (
	testTASecret  = "test-jwt-secret-key-for-signing"
	testCookieKey = "test-cookie-encryption-key-32bytes"
	testDomain    = "example.com"
	testEmail     = "user@example.com"
)

func generateTestToken(secret string, claims *internalJWT.Claims) (string, error) {
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func TestAuthHandler_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	handler := NewAuthHandler(testTASecret, testCookieKey, testDomain, *logger)

	claims := &internalJWT.Claims{
		HTU: "https://example.com/dashboard",
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject:   testEmail,
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  gojwt.NewNumericDate(time.Now()),
		},
	}

	token, err := generateTestToken(testTASecret, claims)
	if err != nil {
		t.Fatalf("failed to generate test token: %v", err)
	}

	req := httptest.NewRequest("GET", "/auth?token="+token, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, w.Code)
	}

	location := w.Header().Get("Location")
	if location != claims.HTU {
		t.Errorf("expected redirect to %s, got %s", claims.HTU, location)
	}

	cookies := w.Result().Cookies()
	var taCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "ta" {
			taCookie = c
			break
		}
	}

	if taCookie == nil {
		t.Fatal("ta cookie was not set")
	}

	if !taCookie.Secure {
		t.Error("cookie Secure flag should be true")
	}
	if !taCookie.HttpOnly {
		t.Error("cookie HttpOnly flag should be true")
	}
	if taCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie SameSite should be Lax, got %v", taCookie.SameSite)
	}
	if taCookie.Path != "/" {
		t.Errorf("cookie Path should be /, got %s", taCookie.Path)
	}
	// Cookie domain should be .example.com or example.com (both are functionally equivalent)
	expectedDomain := ".example.com"
	if taCookie.Domain != expectedDomain && taCookie.Domain != "example.com" {
		t.Errorf("cookie Domain should be %s, got %s", expectedDomain, taCookie.Domain)
	}

	decrypted, err := crypto.Decrypt(taCookie.Value, testCookieKey)
	if err != nil {
		t.Fatalf("failed to decrypt cookie value: %v", err)
	}
	if decrypted != testEmail {
		t.Errorf("decrypted email = %s, want %s", decrypted, testEmail)
	}
}

func TestAuthHandler_MissingToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	handler := NewAuthHandler(testTASecret, testCookieKey, testDomain, *logger)

	req := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAuthHandler_InvalidJWT(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	handler := NewAuthHandler(testTASecret, testCookieKey, testDomain, *logger)

	req := httptest.NewRequest("GET", "/auth?token=invalid.jwt.token", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAuthHandler_ExpiredJWT(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	handler := NewAuthHandler(testTASecret, testCookieKey, testDomain, *logger)

	claims := &internalJWT.Claims{
		HTU: "https://example.com/page",
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject:   testEmail,
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}

	token, err := generateTestToken(testTASecret, claims)
	if err != nil {
		t.Fatalf("failed to generate test token: %v", err)
	}

	req := httptest.NewRequest("GET", "/auth?token="+token, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAuthHandler_DangerousURLScheme(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	handler := NewAuthHandler(testTASecret, testCookieKey, testDomain, *logger)

	dangerousURLs := []string{
		"javascript:alert('xss')",
		"data:text/html,<script>alert('xss')</script>",
		"file:///etc/passwd",
	}

	for _, dangerousURL := range dangerousURLs {
		t.Run(dangerousURL, func(t *testing.T) {
			claims := &internalJWT.Claims{
				HTU: dangerousURL,
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject: testEmail,
				},
			}

			token, err := generateTestToken(testTASecret, claims)
			if err != nil {
				t.Fatalf("failed to generate test token: %v", err)
			}

			req := httptest.NewRequest("GET", "/auth?token="+token, nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected status %d for dangerous URL %s, got %d", http.StatusBadRequest, dangerousURL, w.Code)
			}
		})
	}
}

func TestAuthHandler_DomainMismatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	handler := NewAuthHandler(testTASecret, testCookieKey, testDomain, *logger)

	claims := &internalJWT.Claims{
		HTU: "https://wrong-domain.com/page",
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject: testEmail,
		},
	}

	token, err := generateTestToken(testTASecret, claims)
	if err != nil {
		t.Fatalf("failed to generate test token: %v", err)
	}

	req := httptest.NewRequest("GET", "/auth?token="+token, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAuthHandler_InvalidEmail(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	handler := NewAuthHandler(testTASecret, testCookieKey, testDomain, *logger)

	claims := &internalJWT.Claims{
		HTU: "https://example.com/page",
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject: "not-an-email",
		},
	}

	token, err := generateTestToken(testTASecret, claims)
	if err != nil {
		t.Fatalf("failed to generate test token: %v", err)
	}

	req := httptest.NewRequest("GET", "/auth?token="+token, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestExtractBaseDomain(t *testing.T) {
	tests := []struct {
		hostname string
		want     string
	}{
		// Standard .com domains
		{"app.example.com", ".example.com"},
		{"admin.example.com", ".example.com"},
		{"example.com", ".example.com"},
		{"api.staging.example.com", ".example.com"},

		// Multi-part TLDs (public suffixes)
		{"app.example.co.uk", ".example.co.uk"},
		{"sub.domain.example.co.uk", ".example.co.uk"},
		{"example.co.uk", ".example.co.uk"},
		{"app.example.com.au", ".example.com.au"},

		// Single-label hosts (no Domain attribute)
		{"localhost", ""},

		// Edge cases
		{"app.example.org", ".example.org"},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			got := extractBaseDomain(tt.hostname)
			if got != tt.want {
				t.Errorf("extractBaseDomain(%s) = %s, want %s", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestValidateRedirectURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid https", "https://example.com/page", false},
		{"valid http", "http://example.com/page", false},
		{"javascript scheme", "javascript:alert('xss')", true},
		{"data scheme", "data:text/html,<script>alert('xss')</script>", true},
		{"file scheme", "file:///etc/passwd", true},
		{"ftp scheme", "ftp://example.com/file", true},
		{"invalid URL", "not a valid url", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRedirectURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRedirectURL(%s) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}
