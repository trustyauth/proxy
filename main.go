package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("something went wrong", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
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

	svr := NewServer(config.Origin)
	slog.Info(fmt.Sprintf("server is listening on port %d", config.Port))
	if err := http.ListenAndServe(fmt.Sprintf(":%d", config.Port), svr); err != nil {
		slog.Error("failed to start server", "error", err)
	}

	return nil
}

// Config represents a picket configuration file
type Config struct {
	// Port to listen on
	Port int `yaml:"port"`

	// Origin server to forward requests to
	Origin string `yaml:"origin"`
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
func NewServer(origin string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", proxyHandler(origin))
	return mux
}

func proxyHandler(origin string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()

		originServerURL, err := url.Parse(origin)
		if err != nil {
			slog.Error("failed to parse origin", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		req.Host = originServerURL.Host
		req.URL.Host = originServerURL.Host
		req.URL.Scheme = originServerURL.Scheme
		req.RequestURI = ""

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			slog.Error("failed to proxy request to origin server", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		status := resp.StatusCode
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
