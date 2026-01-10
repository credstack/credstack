/*
Copyright © 2026 Steven A. Zaluk
*/

package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "credstack",
	Short: "",
	Long:  `The open source & cloud-native identity provider`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "~/.credstack/config.json", "config file (default is $HOME/.credstack.yaml)")
	rootCmd.AddCommand(serveCmd)
}
