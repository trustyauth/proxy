package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfig(t *testing.T) {
	t.Run("ReadConfig", func(t *testing.T) {
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
		} else if got, want := c.Addr, ":80"; got != want {
			t.Fatalf("Addr=%v, want %v", got, want)
		} else if got, want := c.Config.Origin, "http://localhost:3000"; got != want {
			t.Fatalf("Origin=%v, want %v", got, want)
		} else if got, want := c.Config.Key, "supersecretkey"; got != want {
			t.Fatalf("Key=%v, want %v", got, want)
		} else if got, want := c.Config.TASecret, "test-jwt-secret"; got != want {
			t.Fatalf("TASecret=%v, want %v", got, want)
		} else if got, want := c.Config.Domain, "example.com"; got != want {
			t.Fatalf("Domain=%v, want %v", got, want)
		}
	})
}
