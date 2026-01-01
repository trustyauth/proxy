package email

import "testing"

func TestIsValid(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  bool
	}{
		{"valid simple", "user@example.com", true},
		{"valid with subdomain", "user@mail.example.com", true},
		{"valid with plus", "user+tag@example.com", true},
		{"valid with dots", "first.last@example.com", true},
		{"empty string", "", false},
		{"missing at", "userexample.com", false},
		{"missing domain", "user@", false},
		{"missing local", "@example.com", false},
		{"double at", "user@@example.com", false},
		{"spaces", "user @example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValid(tt.email); got != tt.want {
				t.Errorf("IsValid(%q) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}
