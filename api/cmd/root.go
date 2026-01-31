/*
Copyright © 2025 Steven A. Zaluk
*/

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/credstack/credstack/api/internal/api"
	"github.com/credstack/credstack/sdk/pkg/config"
	"github.com/spf13/cobra"
)

var cfgFile string
var globalConfig *config.ServerConfig

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
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		err := api.New(globalConfig).Start(ctx)
		if err != nil {
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
	rootCmd.Flags().IntP("api.port", "p", 8080, "The default port that the API is going to listen for requests at")
	rootCmd.Flags().Bool("api.debug", false, "Enables debug mode for the API and disables various options in Fiber. See the docs for more details")
	rootCmd.Flags().Bool("api.prefork", false, "Allows the API to serve requests on multiple processes")
	rootCmd.Flags().Bool("api.skip_preflight", false, "If set to true, then skip API pre-flight checks")
	rootCmd.Flags().StringP("issuer", "i", "https://credstack.issuer.change.me", "The issuer to insert into the claims of issued JWT tokens")

	/*
		Database - Provides options that control how CredStack connects to MongoDB
	*/
	rootCmd.Flags().String("database.hostname", "127.0.0.1", "The hostname of your running MongoDB server")
	rootCmd.Flags().Int("database.port", 27017, "The port of your running MongoDB server")
	rootCmd.Flags().Duration("database.connection_timeout", 15*time.Second, "The number of seconds that MongoDB should wait before closing the connection")
	rootCmd.Flags().Bool("database.use_authentication", true, "If set to true, then authentication options will be evaluated")
	rootCmd.Flags().String("database.default_database", "credstack", "The default database that credstack will initialize in")
	rootCmd.Flags().String("database.authentication_database", "admin", "The default database in MongoDB that provides authentication")
	rootCmd.Flags().String("database.username", "", "The username that credstack will use for authentication with MongoDB")
	rootCmd.Flags().String("database.password", "", "The password that credstack will use for authentication with MongoDB")

	/*
		Log - Provides options that control how logging is handled
	*/
	rootCmd.Flags().String("log.level", "", "The level of logging to use. Can be one of: debug, warn, info. Defaults to info")
	rootCmd.Flags().String("log.path", "/var/log/credstack", "The directory to write log files too")
	rootCmd.Flags().Bool("log.use_file_logging", false, "If set to true, then log files will be written. Otherwise, only STDOUT logging will be used")

	/*
		Credential - Provides options that control how user credentials are hashed
	*/
	rootCmd.Flags().Uint32("argon.time", 1, "The number of iterations that will be made when hashing passwords with Argon2id")
	rootCmd.Flags().Uint32("argon.memory", 1024, "The amount of memory that argon can consume while hashing passwords")
	rootCmd.Flags().Uint8("argon.threads", 1, "The number of goroutines that argon can use while hashing passwords")
	rootCmd.Flags().Uint32("argon.key_length", 16, "The length that passwords will be hashed to")
	rootCmd.Flags().Uint32("argon.salt_length", 32, "The length that a salt will be generated to")
	rootCmd.Flags().Uint32("argon.min_secret_length", 12, "The minimum length requirement of plaintext user credentials")
	rootCmd.Flags().Uint32("argon.max_secret_length", 48, "The maximum length requirement of plaintext user credentials")
}

func initConfig() {
	globalConfig = config.New()
	err := globalConfig.Load(cfgFile) // default needs to be set here!
	if err != nil {
		fmt.Println("Fatal error when loading config: ", err)
		os.Exit(1)
	}
}
