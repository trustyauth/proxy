package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfig(t *testing.T) {
	t.Run("ReadConfig", func(t *testing.T) {
		configFile := filepath.Join(t.TempDir(), "picket.yml")
		if err := os.WriteFile(configFile, []byte(`
port: 80
origins:
  - path: /
    url: http://localhost:3000
  - path: /api
    url: http://localhost:8080
`[1:]), fs.ModePerm); err != nil {
			t.Fatal(err)
		}

		c, err := ReadConfig(configFile)
		if err != nil {
			t.Fatal(err)
		} else if got, want := c.Port, 80; got != want {
			t.Fatalf("Addr=%v, want %v", got, want)
		} else if got, want := c.Origins[0].Path, "/"; got != want {
			t.Fatalf("Origin.Path=%v, want %v", got, want)
		} else if got, want := c.Origins[0].URL, "http://localhost:3000"; got != want {
			t.Fatalf("Origin.URL=%v, want %v", got, want)
		}
	})
}
