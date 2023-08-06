package main

import (
	"bepass-cli/cmd/core"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

func loadConfig() (*core.Config, error) {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config core.Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func main() {
	var configPath string

	config, err := loadConfig()
	if err != nil {
		panic(err)
	}

	rootCmd := &cobra.Command{
		Use:   "cli",
		Short: "cli is a socks5 proxy server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return core.RunServer(config, true)
		},
	}

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "./config.json", "Path to configuration file")
	viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	viper.SetEnvPrefix("cli")
	viper.AutomaticEnv()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
