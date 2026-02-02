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
	Long: `Allows you to manipulate the configuration for the credstack API. Calling 'config' with no arguments will print
out the fully processed configuration for the API. This includes all potential configuration sources (Flag Overrides,
Environment Variables, and Config File). 

Calling the 'init' sub-command will allow you to initialize a new config file with sane defaults, and overrides with the
'--set' flag will be respected. `,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
