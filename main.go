package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

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

	svr := NewServer()
	slog.Info("starting on port", "port", config.Port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", config.Port), svr); err != nil {
		slog.Error("failed to start server", "error", err)
	}

	return nil
}

// Config represents a picket configuration file
type Config struct {
	// Port to listen on
	Port int `yaml:"port"`

	// List of origin servers to forward requests to
	Origins []*OriginConfig `yaml:"origins"`
}

// OriginConfig represents a configuration that maps a relative path to an origin server
type OriginConfig struct {
	Path string `yaml:"path"`
	URL  string `yaml:"url"`
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

func NewServer() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		slog.Info("received request", "path", req.URL.Path)
	})
	return mux
}
