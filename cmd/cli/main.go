// Package main is the entry point for the Bepass application.
package main

import (
	"bepass/config"
	"bepass/logger"
	"bepass/server"
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
		logger.Errorf("%s\n", ffhelp.Flags(fs))
		os.Exit(0)
	case err != nil:
		logger.Errorf("error: %v\n", err)
		os.Exit(1)
	}

	// Load and validate configuration from JSON file
	err = loadConfig(configPath)
	if err != nil {
		logger.Fatal("", err)
	}

	// Run the server with the loaded configuration
	err = server.Run(true)
	if err != nil {
		logger.Fatal("", err)
	}

	// HandleTCPTunnel graceful shutdown
	handleShutdown()
}

func loadConfig(configPath string) error {
	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(config.G)
	if err != nil {
		if strings.Contains(err.Error(), "invalid character") {
			return fmt.Errorf("configuration file is not valid JSON")
		}
		return err
	}

	return nil
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
