package jwt

import (
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

const (
	testSecret = "test-secret-key"
	testDomain = "example.com"
)

func generateToken(secret string, claims *Claims) (string, error) {
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func TestValidator_ValidateToken(t *testing.T) {
	validator := NewValidator(testSecret, testDomain)

	tests := []struct {
		name    string
		claims  *Claims
		secret  string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid token with all claims",
			claims: &Claims{
				HTU: "https://example.com/dashboard",
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject:   "user@example.com",
					ExpiresAt: gojwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
					IssuedAt:  gojwt.NewNumericDate(time.Now()),
					NotBefore: gojwt.NewNumericDate(time.Now()),
				},
			},
			secret:  testSecret,
			wantErr: false,
		},
		{
			name: "valid token without optional time claims",
			claims: &Claims{
				HTU: "https://example.com/page",
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject: "admin@example.com",
				},
			},
			secret:  testSecret,
			wantErr: false,
		},
		{
			name: "valid token with uppercase domain in htu",
			claims: &Claims{
				HTU: "https://Example.COM/page",
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject: "user@example.com",
				},
			},
			secret:  testSecret,
			wantErr: false,
		},
		{
			name: "valid token with trailing dot in htu domain",
			claims: &Claims{
				HTU: "https://example.com./page",
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject: "user@example.com",
				},
			},
			secret:  testSecret,
			wantErr: false,
		},
		{
			name: "valid token with uppercase and trailing dot in htu domain",
			claims: &Claims{
				HTU: "https://Example.COM./page",
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject: "user@example.com",
				},
			},
			secret:  testSecret,
			wantErr: false,
		},
		{
			name: "invalid signature",
			claims: &Claims{
				HTU: "https://example.com/page",
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject: "user@example.com",
				},
			},
			secret:  "wrong-secret",
			wantErr: true,
			errMsg:  "failed to parse token",
		},
		{
			name: "expired token",
			claims: &Claims{
				HTU: "https://example.com/page",
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject:   "user@example.com",
					ExpiresAt: gojwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
				},
			},
			secret:  testSecret,
			wantErr: true,
			errMsg:  "failed to parse token",
		},
		{
			name: "token not yet valid (nbf in future)",
			claims: &Claims{
				HTU: "https://example.com/page",
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject:   "user@example.com",
					NotBefore: gojwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				},
			},
			secret:  testSecret,
			wantErr: true,
			errMsg:  "failed to parse token",
		},
		{
			name: "missing htu claim",
			claims: &Claims{
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject: "user@example.com",
				},
			},
			secret:  testSecret,
			wantErr: true,
			errMsg:  "missing htu claim",
		},
		{
			name: "invalid htu URL",
			claims: &Claims{
				HTU: "not a valid url :// bad",
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject: "user@example.com",
				},
			},
			secret:  testSecret,
			wantErr: true,
			errMsg:  "invalid htu URL",
		},
		{
			name: "htu hostname mismatch",
			claims: &Claims{
				HTU: "https://wrong-domain.com/page",
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject: "user@example.com",
				},
			},
			secret:  testSecret,
			wantErr: true,
			errMsg:  "does not match configured domain",
		},
		{
			name: "missing sub claim",
			claims: &Claims{
				HTU: "https://example.com/page",
			},
			secret:  testSecret,
			wantErr: true,
			errMsg:  "missing sub claim",
		},
		{
			name: "invalid email in sub",
			claims: &Claims{
				HTU: "https://example.com/page",
				RegisteredClaims: gojwt.RegisteredClaims{
					Subject: "not-an-email",
				},
			},
			secret:  testSecret,
			wantErr: true,
			errMsg:  "invalid email in sub claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, err := generateToken(tt.secret, tt.claims)
			if err != nil {
				t.Fatalf("failed to generate test token: %v", err)
			}

			claims, err := validator.ValidateToken(tokenString)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateToken() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateToken() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateToken() unexpected error = %v", err)
				}
				if claims == nil {
					t.Error("ValidateToken() returned nil claims")
				}
				if claims != nil && claims.HTU != tt.claims.HTU {
					t.Errorf("ValidateToken() htu = %v, want %v", claims.HTU, tt.claims.HTU)
				}
				if claims != nil && claims.Subject != tt.claims.Subject {
					t.Errorf("ValidateToken() subject = %v, want %v", claims.Subject, tt.claims.Subject)
				}
			}
		})
	}
}

func TestValidator_RejectsNonHS256Algorithms(t *testing.T) {
	validator := NewValidator(testSecret, testDomain)

	claims := &Claims{
		HTU: "https://example.com/page",
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject: "user@example.com",
		},
	}

	tests := []struct {
		name   string
		method gojwt.SigningMethod
	}{
		{"HS384", gojwt.SigningMethodHS384},
		{"HS512", gojwt.SigningMethodHS512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := gojwt.NewWithClaims(tt.method, claims)
			tokenString, err := token.SignedString([]byte(testSecret))
			if err != nil {
				t.Fatalf("failed to generate test token: %v", err)
			}

			_, err = validator.ValidateToken(tokenString)
			if err == nil {
				t.Errorf("ValidateToken() expected error for %s algorithm, got nil", tt.name)
			}
			if err != nil && !contains(err.Error(), "unexpected signing method") {
				t.Errorf("ValidateToken() error = %v, want error containing 'unexpected signing method'", err)
			}
		})
	}
}

func TestValidator_MalformedToken(t *testing.T) {
	validator := NewValidator(testSecret, testDomain)

	tests := []struct {
		name        string
		tokenString string
	}{
		{
			name:        "empty token",
			tokenString: "",
		},
		{
			name:        "malformed token",
			tokenString: "not.a.valid.jwt",
		},
		{
			name:        "random string",
			tokenString: "abc123xyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.ValidateToken(tt.tokenString)
			if err == nil {
				t.Error("ValidateToken() expected error for malformed token, got nil")
			}
		})
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestNormalizeHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"Example.COM.", "example.com"},
		{"EXAMPLE.COM.", "example.com"},
		{"", ""},
		{".", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeHostname(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeHostname(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
