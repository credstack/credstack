package config

import "time"

// ClientConfig Represents all client configuration options. Primarily used in the API client or the CLI
type ClientConfig struct {
	// Url The Protocol + FQDN + Port to use for API calls made to credstack
	Url string `mapstructure:"url"`

	// Timeout The max amount of time in seconds to wait for a response from the API Server
	Timeout time.Duration `mapstructure:"timeout"`
}

// DefaultClientConfig Initializes the ClientConfig structure with sane defaults
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Url:     "http://localhost:8080",
		Timeout: 10 * time.Second,
	}
}
