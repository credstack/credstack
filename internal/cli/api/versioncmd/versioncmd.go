package versioncmd

import (
	"fmt"

	"github.com/credstack/credstack/internal/version"
	"github.com/spf13/cobra"
)

// NewVersionCommand Initializes a new version command and returns a pointer to it
func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.String())
		},
	}
}
