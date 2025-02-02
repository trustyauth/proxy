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
	"slices"
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

	proxy := proxyHandler(originServerURL)
	mux := http.NewServeMux()
	mux.HandleFunc("/", logMiddleware(csrfMiddleware(config.Key, proxy)))

	server := http.Server{
		Addr:    config.Addr,
		Handler: mux,
	}

	return &server, nil
}

var protectedMethods = []string{"POST", "PUT", "PATCH", "DELETE"}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	// WriteHeader(int) is not called if our response implicitly returns 200 OK, so
	// we default to that status code.
	return &loggingResponseWriter{w, http.StatusOK}
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func logMiddleware(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()

		lrw := NewLoggingResponseWriter(w)
		next(lrw, req)

		end := time.Now()
		slog.Info(req.URL.Path,
			"ip", req.RemoteAddr,
			"method", req.Method,
			"protocol", req.Proto,
			"status", lrw.statusCode,
			"ua", req.UserAgent(),
			"duration", end.Sub(start),
		)
	})
}

func csrfMiddleware(key string, next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if slices.Contains(protectedMethods, req.Method) {
			err := picket.ValidateCSRFToken(req, key)
			if err != nil {
				slog.Error("failed to validate csrf", "error", err)
				w.WriteHeader(http.StatusForbidden)
				return
			}
		} else {
			csrf := picket.NewCSRFToken(key)
			setCookie(w, picket.XSRFCookie, csrf.Token)
			setHeader(w, picket.CSRFHeader, csrf.Token)
		}

		next(w, req)
	})
}

func proxyHandler(origin *url.URL) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		req.Host = origin.Host
		req.URL.Host = origin.Host
		req.URL.Scheme = origin.Scheme
		req.RequestURI = ""

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			slog.Error("failed to proxy request to origin server", "error", err)
			return
		}

		status := resp.StatusCode

		w.WriteHeader(status)
		io.Copy(w, resp.Body)
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
