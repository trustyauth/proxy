package cookie

import (
	"net/http"
	"testing"
)

func TestNew(t *testing.T) {
	c := New("test-name", "test-value")

	if c.Name != "test-name" {
		t.Errorf("expected Name to be 'test-name', got %s", c.Name)
	}
	if c.Value != "test-value" {
		t.Errorf("expected Value to be 'test-value', got %s", c.Value)
	}
	if c.Path != "/" {
		t.Errorf("expected Path to be '/', got %s", c.Path)
	}
	if !c.Secure {
		t.Error("expected Secure to be true")
	}
	if !c.HttpOnly {
		t.Error("expected HttpOnly to be true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite to be Lax, got %v", c.SameSite)
	}
	if c.Domain != "" {
		t.Errorf("expected Domain to be empty, got %s", c.Domain)
	}
}

func TestWithDomain(t *testing.T) {
	c := New("test", "value")
	result := WithDomain(c, ".example.com")

	if result.Domain != ".example.com" {
		t.Errorf("expected Domain to be '.example.com', got %s", result.Domain)
	}
	if result != c {
		t.Error("expected WithDomain to return the same cookie pointer")
	}
}
