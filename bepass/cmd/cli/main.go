package main

import (
	"bepass/cmd/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
)

var configPath string

func loadConfig() {
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath(".")
		viper.SetConfigType("json")
	}
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal(err)
	}
}

func init() {
	cobra.OnInitialize(loadConfig)
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "Bepass",
		Short: "Bepass is an Anti DPI and anti censorship proxy solution",
		Run: func(cmd *cobra.Command, args []string) {
			config := &core.Config{}
			err := viper.Unmarshal(&config)
			if err != nil {
				log.Fatal(err)
			}
			err = core.RunServer(config, true)
			if err != nil {
				log.Fatal(err)
			}
		},
	}

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "./config.json", "Path to configuration file")
	err := viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	if err != nil {
		log.Fatal(err)
	}
	viper.SetEnvPrefix("Bepass")

	err = rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
