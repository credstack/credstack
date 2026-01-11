/*
Copyright © 2025 Steven A. Zaluk
*/

package cmd

import (
	"os"
	"time"

	"context"

	"github.com/credstack/credstack/internal/api"
	"github.com/spf13/cobra"
)

// serveCmd Represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Credstack API Server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		err := api.New(globalConfig).Start(ctx)
		if err != nil {
			os.Exit(1)
		}
	},
}

func init() {
	serveCmd.Flags().IntP("api.port", "p", 8080, "The default port that the API is going to listen for requests at")
	serveCmd.Flags().Bool("api.debug", false, "Enables debug mode for the API and disables various options in Fiber. See the docs for more details")
	serveCmd.Flags().Bool("api.prefork", false, "Allows the API to serve requests on multiple processes")
	serveCmd.Flags().Bool("api.skip_preflight", false, "If set to true, then skip API pre-flight checks")
	serveCmd.Flags().StringP("issuer", "i", "https://credstack.issuer.change.me", "The issuer to insert into the claims of issued JWT tokens")

	/*
		Database - Provides options that control how CredStack connects to MongoDB
	*/
	serveCmd.Flags().String("database.hostname", "127.0.0.1", "The hostname of your running MongoDB server")
	serveCmd.Flags().Int("database.port", 27017, "The port of your running MongoDB server")
	serveCmd.Flags().Int("database.connection_timeout", 15, "The number of seconds that MongoDB should wait before closing the connection")
	serveCmd.Flags().Bool("database.use_authentication", true, "If set to true, then authentication options will be evaluated")
	serveCmd.Flags().String("database.default_database", "credstack", "The default database that credstack will initialize in")
	serveCmd.Flags().String("database.authentication_database", "admin", "The default database in MongoDB that provides authentication")
	serveCmd.Flags().String("database.username", "", "The username that credstack will use for authentication with MongoDB")
	serveCmd.Flags().String("database.password", "", "The password that credstack will use for authentication with MongoDB")

	/*
		Log - Provides options that control how logging is handled
	*/
	serveCmd.Flags().String("log.level", "", "The level of logging to use. Can be one of: debug, warn, info. Defaults to info")
	serveCmd.Flags().String("log.path", "/var/log/credstack", "The directory to write log files too")
	serveCmd.Flags().Bool("log.use_file_logging", false, "If set to true, then log files will be written. Otherwise, only STDOUT logging will be used")

	/*
		Credential - Provides options that control how user credentials are hashed
	*/
	serveCmd.Flags().Uint32("argon.time", 1, "The number of iterations that will be made when hashing passwords with Argon2id")
	serveCmd.Flags().Uint32("argon.memory", 1024, "The amount of memory that argon can consume while hashing passwords")
	serveCmd.Flags().Uint8("argon.threads", 1, "The number of goroutines that argon can use while hashing passwords")
	serveCmd.Flags().Uint32("argon.key_length", 16, "The length that passwords will be hashed to")
	serveCmd.Flags().Uint32("argon.salt_length", 32, "The length that a salt will be generated to")
	serveCmd.Flags().Uint32("argon.min_secret_length", 12, "The minimum length requirement of plaintext user credentials")
	serveCmd.Flags().Uint32("argon.max_secret_length", 48, "The maximum length requirement of plaintext user credentials")
}
