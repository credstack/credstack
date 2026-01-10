package config

import "github.com/spf13/viper"

// Config Global configuration values for the entire application
type Config struct {
	// viper The viper instance that all configuration values will be stored under
	viper *viper.Viper

	// DatabaseConfig All database configuration options
	DatabaseConfig *DatabaseConfig

	// ApiConfig All API configuration options
	ApiConfig *ApiConfig

	// LogConfig All logging configuration options
	LogConfig *LogConfig

	// CredentialConfig All user credential configuration options
	CredentialConfig *CredentialConfig
}

// New Initializes a new config structure along with a viper instance for values to be stored under
func New() *Config {
	config := &Config{
		viper: viper.New(),
	}

	return config
}
