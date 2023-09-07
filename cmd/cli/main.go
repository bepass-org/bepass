// Package main is the entry point for the Bepass application.
package main

import (
	"bepass/cmd/core"
	"bepass/logger"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

var configPath string

func main() {
	fs := ff.NewFlags("Bepass")
	fs.StringVar(&configPath, 'c', "config", "./config.json", "Path to configuration file")

	err := ff.Parse(fs, os.Args[1:])
	switch {
	case errors.Is(err, ff.ErrHelp):
		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Flags(fs))
		os.Exit(0)
	case err != nil:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Load and validate configuration from JSON file
	config, err := loadConfig(configPath)
	if err != nil {
		logger.Fatal("", err)
	}

	// Run the server with the loaded configuration
	fmt.Printf("Config: %+v\n", config)
	err = core.RunServer(config, true)
	if err != nil {
		logger.Fatal("", err)
	}

	// Handle graceful shutdown
	handleShutdown()
}

func loadConfig(configPath string) (*core.Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &core.Config{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		if strings.Contains(err.Error(), "invalid character") {
			return nil, fmt.Errorf("configuration file is not valid JSON")
		}
		return nil, err
	}

	return config, nil
}

func handleShutdown() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received.
	<-c

	// Perform cleanup or shutdown tasks here.
	fmt.Println("Shutting down gracefully...")
	os.Exit(0)
}
