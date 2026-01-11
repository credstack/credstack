/*
Copyright © 2026 Steven A. Zaluk
*/

package cmd

import (
	"fmt"
	"os"

	"github.com/credstack/credstack/internal/config"
	"github.com/spf13/cobra"
)

var cfgFile string
var globalConfig *config.Config

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "credstack",
	Short: "",
	Long:  `The open source & cloud-native identity provider`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		err := globalConfig.BindFlags(cmd)
		if err != nil {
			fmt.Println("Fatal error when binding flags: ", err)
			os.Exit(1)
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "~/.credstack/config.json", "Set the the config file to load")
	rootCmd.AddCommand(serveCmd)
}

func initConfig() {
	globalConfig = config.New()
	err := globalConfig.Load(cfgFile) // default needs to be set here!
	if err != nil {
		fmt.Println("Fatal error when loading config: ", err)
		os.Exit(1)
	}
}
