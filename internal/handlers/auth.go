package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/trustyauth/proxy/internal/cookie"
	"github.com/trustyauth/proxy/internal/crypto"
	"github.com/trustyauth/proxy/internal/jwt"
)

const (
	HeaderReferrerPolicy      = "Referrer-Policy"
	HeaderReferrerPolicyValue = "no-referrer"
)

// AuthHandler handles JWT token validation and sets authentication cookies.
type AuthHandler struct {
	validator *jwt.Validator
	cookieKey string
	logger    slog.Logger
}

// NewAuthHandler creates a new AuthHandler with the given configuration.
func NewAuthHandler(taSecret, cookieKey, domain string, logger slog.Logger) *AuthHandler {
	return &AuthHandler{
		validator: jwt.NewValidator(taSecret, domain),
		cookieKey: cookieKey,
		logger:    logger,
	}
}

// ServeHTTP validates JWT tokens and sets authentication cookies.
func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		h.logger.Error("missing token query parameter", "path", r.URL.Path, "ip", r.RemoteAddr)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	claims, err := h.validator.ValidateToken(token)
	if err != nil {
		h.logger.Error("JWT validation failed", "error", err, "ip", r.RemoteAddr)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if err := validateRedirectURL(claims.HTU); err != nil {
		h.logger.Error("invalid redirect URL", "error", err, "htu", claims.HTU, "ip", r.RemoteAddr)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	htuURL, err := url.Parse(claims.HTU)
	if err != nil {
		h.logger.Error("failed to parse htu URL", "error", err, "htu", claims.HTU, "ip", r.RemoteAddr)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	baseDomain := extractBaseDomain(htuURL.Hostname())

	encryptedEmail, err := crypto.Encrypt(claims.Subject, h.cookieKey)
	if err != nil {
		h.logger.Error("failed to encrypt email", "error", err, "ip", r.RemoteAddr)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, cookie.WithDomain(cookie.New(cookie.Auth, encryptedEmail), baseDomain))

	h.logger.Info("authentication successful", "email", claims.Subject, "redirect", claims.HTU, "ip", r.RemoteAddr)

	w.Header().Set(HeaderReferrerPolicy, HeaderReferrerPolicyValue)
	http.Redirect(w, r, claims.HTU, http.StatusFound)
}

func validateRedirectURL(urlStr string) error {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsafe URL scheme: %s (only http and https are allowed)", scheme)
	}

	return nil
}

// extractBaseDomain extracts the registrable domain for cookie sharing.
// Uses the Public Suffix List to correctly handle multi-part TLDs.
// For example:
//   - app.example.com -> .example.com
//   - app.example.co.uk -> .example.co.uk
//   - localhost -> "" (empty, lets browser default to exact host)
func extractBaseDomain(hostname string) string {
	// Single-label hosts (e.g., localhost) should not have a Domain set
	// so the cookie is scoped to the exact host
	if !strings.Contains(hostname, ".") {
		return ""
	}

	// Use the Public Suffix List to get the registrable domain
	// (eTLD+1, e.g., "example.co.uk" for "app.example.co.uk")
	registrable, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		// If we can't determine the registrable domain, omit Domain
		// to let the browser default to the exact host
		return ""
	}

	return "." + registrable
}
