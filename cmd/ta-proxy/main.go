package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trustyauth/proxy"
	"github.com/trustyauth/proxy/internal/crypto"
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		slog.Error("something went wrong", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ta-proxy", flag.ContinueOnError)
	configFlag := fs.String("config", "", "config path")
	err := fs.Parse(args)
	if err != nil {
		return err
	}

	config, err := ReadConfig(*configFlag)
	if err != nil {
		return err
	}

	if config.Origin == "" {
		return fmt.Errorf("must specify origin server")
	}

	if len(config.Key) < crypto.MinKeyLength {
		return fmt.Errorf("key must be at least %d bytes (current: %d bytes)", crypto.MinKeyLength, len(config.Key))
	}

	if config.TASecret == "" {
		return fmt.Errorf("must specify ta_secret for JWT authentication")
	}

	if config.Domain == "" {
		return fmt.Errorf("must specify domain for JWT hostname validation")
	}

	server, err := NewServer(&config)
	if err != nil {
		return err
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("server is listening on %s", config.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("failed to start server", "error", err)
		}
	}()

	<-done
	slog.Info("server shutting down...")

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer func() {
		cancel()
	}()

	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error shutting down server: %s\n", err)
	}

	return nil
}

// Config represents a trustyauth configuration file
type Config struct {
	// Bind addr
	Addr string `yaml:"addr"`

	// Proxy configuration (embedded)
	proxy.Config `yaml:",inline"`
}

// ReadConfig unmarshals the config from a file
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

// NewServer returns a new ServeMux with the appropriate handlers registered
func NewServer(config *Config) (*http.Server, error) {
	rp, err := proxy.NewReverseProxy(&config.Config, *slog.Default())
	if err != nil {
		slog.Error("failed to create reverse proxy", "error", err)
		return nil, err
	}

	server := http.Server{
		Addr:    config.Addr,
		Handler: rp.Mux,
	}

	return &server, nil
}
