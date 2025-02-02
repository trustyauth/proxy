package main

import (
	"context"
	"flag"
	"fmt"
	"io"
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", proxyHandler(originServerURL, config.Key))

	server := http.Server{
		Addr:    config.Addr,
		Handler: mux,
	}

	return &server, nil
}

func proxyHandler(origin *url.URL, key string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()

		req.Host = origin.Host
		req.URL.Host = origin.Host
		req.URL.Scheme = origin.Scheme
		req.RequestURI = ""

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			slog.Error("failed to proxy request to origin server", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		status := resp.StatusCode

		csrf := picket.NewCSRFToken(key, "tyler@example.com", req.Method, req.URL.Path)
		setCookie(w, picket.XSRFCookie, csrf.Token)
		setHeader(w, picket.CSRFHeader, csrf.Token)

		w.WriteHeader(status)
		io.Copy(w, resp.Body)

		end := time.Now()
		slog.Info(req.URL.Path,
			"ip", req.RemoteAddr,
			"method", req.Method,
			"protocol", req.Proto,
			"status", status,
			"ua", req.UserAgent(),
			"duration", end.Sub(start),
		)
	}
}

func setCookie(w http.ResponseWriter, name, value string) {
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
}

func setHeader(w http.ResponseWriter, name, value string) {
	w.Header().Set(name, value)
}
