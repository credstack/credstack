package config

import (
	"os"
	"path"
	"strings"

	"github.com/spf13/viper"
)

// Config Global configuration values for the entire application
type Config struct {
	// viper The viper instance that all configuration values will be stored under
	viper *viper.Viper

	// DatabaseConfig All database configuration options
	DatabaseConfig *DatabaseConfig `mapstructure:"database"`

	// ApiConfig All API configuration options
	ApiConfig *ApiConfig `mapstructure:"api"`

	// LogConfig All logging configuration options
	LogConfig *LogConfig `mapstructure:"log"`

	// CredentialConfig All user credential configuration options
	CredentialConfig *CredentialConfig `mapstructure:"credential"`
}

// Load Loads the config from the requested file path and falls back to environmental variables
// if the file was not found
func (config *Config) Load(configPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	sanitizedPath := strings.Replace(configPath, "~", home, 1)

	config.viper.AddConfigPath(path.Dir(sanitizedPath))
	config.viper.SetConfigType("json")
	config.viper.SetConfigName("config.json")

	err = config.viper.ReadInConfig()
	if err != nil {
		// Config file was not found, so lets fall back to environmental variables
		viper.SetEnvPrefix("CREDSTACK")
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
		viper.AutomaticEnv()
	}

	return nil
}

// New Initializes a new config structure along with a viper instance for values to be stored under
func New() *Config {
	config := &Config{
		viper: viper.New(),
	}

	return config
}
