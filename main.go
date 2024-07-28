package main

import (
	"flag"
	"fmt"
	"log/slog"
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

	_, err = ReadConfig(*configFlag)
	if err != nil {
		return err
	}

	return nil
}

// Config represents a picket configuration file
type Config struct {
	// Address to listen for requests
	Addr string `yaml:"addr"`

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
