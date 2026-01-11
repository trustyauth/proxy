package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

func (s *Server) tlsPort() string {
	_, port, err := net.SplitHostPort(s.config.Addr)
	if err != nil {
		// Addr might be just ":443" - strip leading colon
		return strings.TrimPrefix(s.config.Addr, ":")
	}
	return port
}

func (s *Server) startHTTPRedirect() error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract hostname, stripping port if present
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		if host == "" {
			host = s.config.Domain
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		// Build target URL; append port if non-standard
		target := "https://" + host
		if port := s.tlsPort(); port != "443" && port != "" {
			target += ":" + port
		}
		target += r.URL.RequestURI()

		slog.Info("redirecting to HTTPS",
			"from", r.URL.RequestURI(),
			"to", target,
			"remote_addr", r.RemoteAddr,
		)

		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})

	listener, err := net.Listen("tcp", s.config.TLS.HTTPRedirect)
	if err != nil {
		return err
	}

	s.redirectServer = &http.Server{Addr: s.config.TLS.HTTPRedirect, Handler: handler}

	go func() {
		slog.Info("starting HTTP redirect listener", "addr", s.config.TLS.HTTPRedirect)
		if err := s.redirectServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP redirect listener failed", "error", err)
		}
	}()

	return nil
}

// ListenAndServe starts the server based on the configured TLS mode.
func (s *Server) ListenAndServe() error {
	// Start HTTP redirect listener if configured (for TLS modes)
	if s.config.TLS.Mode == "manual" && s.config.TLS.HTTPRedirect != "" {
		if err := s.startHTTPRedirect(); err != nil {
			return fmt.Errorf("failed to start HTTP redirect listener: %w", err)
		}
	}

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

// Shutdown gracefully shuts down the server and redirect listener.
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error

	// Shutdown redirect server if running
	if s.redirectServer != nil {
		slog.Info("shutting down HTTP redirect listener")
		if err := s.redirectServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("redirect server: %w", err))
		}
	}

	// Shutdown main server
	slog.Info("shutting down main server")
	if err := s.server.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("main server: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
