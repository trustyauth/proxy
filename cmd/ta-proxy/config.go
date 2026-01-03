package main

import (
	"fmt"
	"os"

	"github.com/trustyauth/proxy"
	"gopkg.in/yaml.v3"
)

// Config represents a trustyauth configuration file.
type Config struct {
	// Addr specifies the addr to bind the server to.
	Addr string `yaml:"addr"`

	// TLS specifies the TLS termination configuration.
	TLS TLSConfig `yaml:"tls"`

	// Proxy configuration (embedded).
	proxy.Config `yaml:",inline"`
}

// TLSConfig configures TLS termination mode.
type TLSConfig struct {
	// Mode specifies the TLS mode: "off", "manual", or "acme".
	Mode string `yaml:"mode"`

	// Manual contains certificate paths for manual mode.
	Manual *ManualTLS `yaml:"manual"`

	// ACME contains Let's Encrypt configuration for acme mode.
	ACME *ACMEConfig `yaml:"acme"`

	// HTTPRedirect specifies an address (e.g. ":80") for HTTP-to-HTTPS redirect.
	HTTPRedirect string `yaml:"http_redirect"`
}

// ManualTLS contains paths to certificate files.
type ManualTLS struct {
	// Cert is the path to the certificate PEM file.
	Cert string `yaml:"cert"`

	// Key is the path to the private key PEM file.
	Key string `yaml:"key"`
}

// ACMEConfig contains Let's Encrypt ACME configuration.
type ACMEConfig struct {
	// Domains is the list of domains for certificate issuance.
	Domains []string `yaml:"domains"`

	// CacheDir is the directory to cache certificates.
	CacheDir string `yaml:"cache_dir"`

	// Email is an optional contact email for Let's Encrypt.
	Email string `yaml:"email"`
}

// ReadConfig unmarshals the config from a file.
func ReadConfig(filename string) (c Config, err error) {
	buf, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		err = fmt.Errorf("missing config file: %s", filename)
		return
	} else if err != nil {
		return
	}

	err = yaml.Unmarshal(buf, &c)
	if err != nil {
		return
	}

	return
}
