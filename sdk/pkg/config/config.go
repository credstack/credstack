package config

import "github.com/spf13/viper"

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

// New Initialize a new ServerConfig structure
func New() *ServerConfig {
	return &ServerConfig{viper: viper.New()}
}
