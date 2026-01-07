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
	"golang.org/x/crypto/acme/autocert"
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

// Server wraps the HTTP server with TLS configuration and lifecycle management.
type Server struct {
	server         *http.Server
	redirectServer *http.Server
	acmeManager    *autocert.Manager
	config         *Config
}

// NewServer returns a new Server with the appropriate handlers registered.
func NewServer(config *Config) (*Server, error) {
	rp, err := proxy.NewReverseProxy(&config.Config, *slog.Default())
	if err != nil {
		slog.Error("failed to create reverse proxy", "error", err)
		return nil, err
	}

	httpServer := &http.Server{
		Addr:    config.Addr,
		Handler: rp.Mux,
	}

	return &Server{
		server: httpServer,
		config: config,
	}, nil
}

// ListenAndServe starts the server based on the configured TLS mode.
func (s *Server) ListenAndServe() error {
	switch s.config.TLS.Mode {
	case "manual":
		slog.Info("starting server with manual TLS",
			"addr", s.config.Addr,
			"cert", s.config.TLS.Manual.Cert,
			"key", s.config.TLS.Manual.Key,
		)
		return s.server.ListenAndServeTLS(
			s.config.TLS.Manual.Cert,
			s.config.TLS.Manual.Key,
		)
	case "acme":
		return fmt.Errorf("acme mode is not yet implemented")
	default:
		// "off" or empty string - plain HTTP
		slog.Info("starting server without TLS", "addr", s.config.Addr)
		return s.server.ListenAndServe()
	}
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
