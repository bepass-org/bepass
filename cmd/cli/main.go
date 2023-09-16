// Package main is the entry point for the Bepass application.
package main

import (
	"bepass/config"
	"bepass/pkg/logger"
	"bepass/server"
	"errors"
	"flag"
	"fmt"
	"os"
)

const (
	// Version is the current version of the application.
	Version       = "2.0.0-alpha"
	DefaultConfig = "config.json"
)

func main() {

	configFile := flag.String("config", "config.json", "Configuration file location")
	configShort := flag.String("c", "config.json", "Configuration file (shorthand)")

	showHelp := flag.Bool("help", false, "Show help message")
	helpShort := flag.Bool("h", false, "Show help (shorthand)")

	showVersion := flag.Bool("version", false, "Show version")
	versionShort := flag.Bool("v", false, "Show version (shorthand)")

	flag.Parse()

	if *showHelp || *helpShort {
		printHelp()
		return
	}

	if *showVersion || *versionShort {
		printVersion()
		return
	}

	if (configFile == nil || *configFile == "") && (configShort == nil || *configShort == "") {
		if _, err := os.Stat(DefaultConfig); errors.Is(err, os.ErrNotExist) {
			logger.Fatalf("config file not found: %v", err.Error())
		}
		config.FromFile(DefaultConfig)
	} else if configFile != nil && *configFile != "" {
		if _, err := os.Stat(*configFile); errors.Is(err, os.ErrNotExist) {
			logger.Fatalf("config file not found: %v", err.Error())
		}
		config.FromFile(*configFile)
	} else if configFile != nil && *configFile != "" {
		if _, err := os.Stat(*configFile); errors.Is(err, os.ErrNotExist) {
			logger.Fatalf("config file not found: %v", err.Error())
		}
		config.FromFile(*configFile)
	}
	err := server.Run(true)
	if err != nil {
		logger.Fatalf("failed to start server: %v", err)
	}
}

func printHelp() {
	fmt.Println("Usage:")
	flag.PrintDefaults()
}

func printVersion() {
	fmt.Println("Version:", Version)
}
