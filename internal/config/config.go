package config

// Config Global configuration values for the entire application
type Config struct {
	// DatabaseConfig All database configuration options
	DatabaseConfig *DatabaseConfig

	ApiConfig *ApiConfig

	LogConfig *LogConfig

	CredentialConfig *CredentialConfig
}
