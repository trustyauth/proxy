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

	if err := config.TLS.Validate(); err != nil {
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
