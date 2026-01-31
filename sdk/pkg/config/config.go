package config

import (
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type ServerConfig struct {
	// viper The viper instance that will store configuration values
	viper *viper.Viper

	// ApiConfig All API Configuration options
	ApiConfig ApiConfig `mapstructure:"api"`

	// DatabaseConfig All Database configuration options
	DatabaseConfig DatabaseConfig `mapstructure:"database"`

	// CredentialConfig All options for controlling how user passwords are hashed
	CredentialConfig CredentialConfig `mapstructure:"credential"`

	// LogConfig All options for controlling how logs are generated/written
	LogConfig LogConfig `mapstructure:"log"`
}

// sanitizePath Performs basic sanitation on user provided paths
func (config *ServerConfig) sanitizePath(configPath string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return strings.Replace(configPath, "~", home, 1), nil
}

// BindFlags A wrapper around viper.BindPFlags that provides access to the viper instance that the config
// structure keeps track of
func (config *ServerConfig) BindFlags(cmd *cobra.Command) error {
	err := config.viper.BindPFlags(cmd.Flags())
	if err != nil {
		return err
	}

	err = config.viper.Unmarshal(&config)
	if err != nil {
		return err
	}

	return nil
}

// Write Writes the current configuration structure back to the config file
func (config *ServerConfig) Write(configPath string) error {
	sanitized, err := config.sanitizePath(configPath)
	if err != nil {
		return err
	}

	err = config.viper.WriteConfigAs(sanitized)
	if err != nil {
		return err
	}

	return nil
}

// Load Loads the config from the requested file path and falls back to environmental variables
// if the file was not found
func (config *ServerConfig) Load(configPath string) error {
	sanitized, err := config.sanitizePath(configPath)
	if err != nil {
		return err
	}

	config.viper.AddConfigPath(path.Dir(sanitized))
	config.viper.SetConfigType("json")
	config.viper.SetConfigName("config.json")

	err = config.viper.ReadInConfig()
	if err != nil {
		// Config file was not found, so lets fall back to environmental variables
		viper.SetEnvPrefix("CREDSTACK")
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
		viper.AutomaticEnv()
	}

	// Always unmarshal all viper keys to our Config structure
	err = config.viper.Unmarshal(&config)
	if err != nil {
		return err
	}

	return nil
}

// New Initialize a new ServerConfig structure
func New() *ServerConfig {
	return &ServerConfig{viper: viper.New()}
}
