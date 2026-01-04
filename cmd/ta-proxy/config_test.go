package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfig(t *testing.T) {
	t.Run("parses basic config with TLS defaulting to empty mode", func(t *testing.T) {
		configFile := filepath.Join(t.TempDir(), "trustyauth.yml")
		if err := os.WriteFile(configFile, []byte(`
addr: :80
origin: http://localhost:3000
key: supersecretkey
ta_secret: test-jwt-secret
domain: example.com
`[1:]), fs.ModePerm); err != nil {
			t.Fatal(err)
		}

		c, err := ReadConfig(configFile)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := c.Addr, ":80"; got != want {
			t.Fatalf("Addr=%v, want %v", got, want)
		}
		if got, want := c.Config.Origin, "http://localhost:3000"; got != want {
			t.Fatalf("Origin=%v, want %v", got, want)
		}
		if got, want := c.Config.Key, "supersecretkey"; got != want {
			t.Fatalf("Key=%v, want %v", got, want)
		}
		if got, want := c.Config.TASecret, "test-jwt-secret"; got != want {
			t.Fatalf("TASecret=%v, want %v", got, want)
		}
		if got, want := c.Config.Domain, "example.com"; got != want {
			t.Fatalf("Domain=%v, want %v", got, want)
		}
		if c.TLS.Mode != "" {
			t.Errorf("TLS.Mode = %q, want empty string", c.TLS.Mode)
		}
		if err := c.TLS.Validate(); err != nil {
			t.Errorf("TLS.Validate() returned error for empty mode: %v", err)
		}
	})

	t.Run("parses TLS off mode", func(t *testing.T) {
		configFile := filepath.Join(t.TempDir(), "trustyauth.yml")
		if err := os.WriteFile(configFile, []byte(`
addr: :80
origin: http://localhost:3000
key: supersecretkey
ta_secret: test-jwt-secret
domain: example.com
tls:
  mode: "off"
`[1:]), fs.ModePerm); err != nil {
			t.Fatal(err)
		}

		c, err := ReadConfig(configFile)
		if err != nil {
			t.Fatal(err)
		}
		if c.TLS.Mode != "off" {
			t.Errorf("TLS.Mode = %q, want %q", c.TLS.Mode, "off")
		}
	})

	t.Run("parses TLS manual mode", func(t *testing.T) {
		configFile := filepath.Join(t.TempDir(), "trustyauth.yml")
		if err := os.WriteFile(configFile, []byte(`
addr: :443
origin: http://localhost:3000
key: supersecretkey
ta_secret: test-jwt-secret
domain: example.com
tls:
  mode: "manual"
  manual:
    cert: "/etc/ssl/cert.pem"
    key: "/etc/ssl/key.pem"
  http_redirect: ":80"
`[1:]), fs.ModePerm); err != nil {
			t.Fatal(err)
		}

		c, err := ReadConfig(configFile)
		if err != nil {
			t.Fatal(err)
		}
		if c.TLS.Mode != "manual" {
			t.Errorf("TLS.Mode = %q, want %q", c.TLS.Mode, "manual")
		}
		if c.TLS.Manual == nil {
			t.Fatal("TLS.Manual is nil")
		}
		if c.TLS.Manual.Cert != "/etc/ssl/cert.pem" {
			t.Errorf("TLS.Manual.Cert = %q, want %q", c.TLS.Manual.Cert, "/etc/ssl/cert.pem")
		}
		if c.TLS.Manual.Key != "/etc/ssl/key.pem" {
			t.Errorf("TLS.Manual.Key = %q, want %q", c.TLS.Manual.Key, "/etc/ssl/key.pem")
		}
		if c.TLS.HTTPRedirect != ":80" {
			t.Errorf("TLS.HTTPRedirect = %q, want %q", c.TLS.HTTPRedirect, ":80")
		}
	})

	t.Run("parses TLS acme mode", func(t *testing.T) {
		configFile := filepath.Join(t.TempDir(), "trustyauth.yml")
		if err := os.WriteFile(configFile, []byte(`
addr: :443
origin: http://localhost:3000
key: supersecretkey
ta_secret: test-jwt-secret
domain: example.com
tls:
  mode: "acme"
  acme:
    domains: ["example.com", "www.example.com"]
    cache_dir: "/var/cache/certs"
    email: "admin@example.com"
  http_redirect: ":80"
`[1:]), fs.ModePerm); err != nil {
			t.Fatal(err)
		}

		c, err := ReadConfig(configFile)
		if err != nil {
			t.Fatal(err)
		}
		if c.TLS.Mode != "acme" {
			t.Errorf("TLS.Mode = %q, want %q", c.TLS.Mode, "acme")
		}
		if c.TLS.ACME == nil {
			t.Fatal("TLS.ACME is nil")
		}
		wantDomains := []string{"example.com", "www.example.com"}
		if len(c.TLS.ACME.Domains) != len(wantDomains) {
			t.Errorf("TLS.ACME.Domains = %v, want %v", c.TLS.ACME.Domains, wantDomains)
		} else {
			for i, d := range c.TLS.ACME.Domains {
				if d != wantDomains[i] {
					t.Errorf("TLS.ACME.Domains[%d] = %q, want %q", i, d, wantDomains[i])
				}
			}
		}
		if c.TLS.ACME.CacheDir != "/var/cache/certs" {
			t.Errorf("TLS.ACME.CacheDir = %q, want %q", c.TLS.ACME.CacheDir, "/var/cache/certs")
		}
		if c.TLS.ACME.Email != "admin@example.com" {
			t.Errorf("TLS.ACME.Email = %q, want %q", c.TLS.ACME.Email, "admin@example.com")
		}
		if c.TLS.HTTPRedirect != ":80" {
			t.Errorf("TLS.HTTPRedirect = %q, want %q", c.TLS.HTTPRedirect, ":80")
		}
	})

	t.Run("missing config file returns error", func(t *testing.T) {
		_, err := ReadConfig("/nonexistent/path/config.yml")
		if err == nil {
			t.Error("ReadConfig() expected error for missing file, got nil")
		}
	})
}

func TestTLSConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  TLSConfig
		wantErr string
	}{
		// Valid configurations
		{
			name:    "off mode is valid",
			config:  TLSConfig{Mode: "off"},
			wantErr: "",
		},
		{
			name:    "empty mode is valid (defaults to off)",
			config:  TLSConfig{Mode: ""},
			wantErr: "",
		},
		{
			name: "manual mode with cert and key is valid",
			config: TLSConfig{
				Mode: "manual",
				Manual: &ManualTLS{
					Cert: "/path/to/cert.pem",
					Key:  "/path/to/key.pem",
				},
			},
			wantErr: "",
		},
		{
			name: "acme mode with domains and cache_dir is valid",
			config: TLSConfig{
				Mode: "acme",
				ACME: &ACMEConfig{
					Domains:  []string{"example.com"},
					CacheDir: "/var/cache/certs",
				},
			},
			wantErr: "",
		},

		// Invalid mode
		{
			name:    "invalid mode returns error",
			config:  TLSConfig{Mode: "invalid"},
			wantErr: "invalid tls.mode: \"invalid\" (must be 'off', 'manual', or 'acme')",
		},

		// Manual mode errors
		{
			name:    "manual mode without manual config returns error",
			config:  TLSConfig{Mode: "manual"},
			wantErr: "tls.manual config required when mode is 'manual'",
		},
		{
			name: "manual mode without cert returns error",
			config: TLSConfig{
				Mode: "manual",
				Manual: &ManualTLS{
					Key: "/path/to/key.pem",
				},
			},
			wantErr: "tls.manual.cert is required",
		},
		{
			name: "manual mode without key returns error",
			config: TLSConfig{
				Mode: "manual",
				Manual: &ManualTLS{
					Cert: "/path/to/cert.pem",
				},
			},
			wantErr: "tls.manual.key is required",
		},

		// ACME mode errors
		{
			name:    "acme mode without acme config returns error",
			config:  TLSConfig{Mode: "acme"},
			wantErr: "tls.acme config required when mode is 'acme'",
		},
		{
			name: "acme mode without domains returns error",
			config: TLSConfig{
				Mode: "acme",
				ACME: &ACMEConfig{
					CacheDir: "/var/cache/certs",
				},
			},
			wantErr: "tls.acme.domains is required",
		},
		{
			name: "acme mode without cache_dir returns error",
			config: TLSConfig{
				Mode: "acme",
				ACME: &ACMEConfig{
					Domains: []string{"example.com"},
				},
			},
			wantErr: "tls.acme.cache_dir is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() returned unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error %q, got nil", tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("Validate() error = %q, want %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}
