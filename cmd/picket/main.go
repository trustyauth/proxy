package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tjmcginnis/picket"
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		slog.Error("something went wrong", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("picket", flag.ContinueOnError)
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

// Config represents a picket configuration file
type Config struct {
	// Bind addr
	Addr string `yaml:"addr"`

	// Origin server to forward requests to
	Origin string `yaml:"origin"`

	// Signing key
	Key string `yaml:"key"`
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
	originServerURL, err := url.Parse(config.Origin)
	if err != nil {
		slog.Error("failed to parse origin", "error", err)
		return nil, err
	}

	proxy := picket.NewReverseProxy(originServerURL, config.Key, *slog.Default())
	server := http.Server{
		Addr:    config.Addr,
		Handler: proxy.Mux,
	}

	return &server, nil
}
