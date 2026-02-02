/*
Copyright © 2026 Steven A. Zaluk
*/

package cmd

import (
	"github.com/spf13/cobra"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Perform operations on API configuration",
	Long: `Allows you to manipulate the config file for the credstack API. Calling 'config' with no arguments will print
out the fully process config file as the API would read it at runtime allowing you to resolve potential issues with your
config file. 

Calling the 'init' sub-command will allow you to initialize a new config file with sane defaults, and overrides with the
'--set' flag will be respected. `,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
