package config

import "github.com/spf13/viper"

// Config Global configuration values for the entire application
type Config struct {
	viper *viper.Viper

	// DatabaseConfig All database configuration options
	DatabaseConfig *DatabaseConfig

	ApiConfig *ApiConfig

	LogConfig *LogConfig

	CredentialConfig *CredentialConfig
}

// New Initializes a new config structure along with a viper instance for values to be stored under
func New() *Config {
	config := &Config{
		viper: viper.New(),
	}

	return config
}
