package config

// ClientConfig Represents all client configuration options. Primarily used in the API client or the CLI
type ClientConfig struct {
	// Url The Protocol + FQDN + Port to use for API calls made to credstack
	Url string `mapstructure:"url"`
}

// DefaultClientConfig Initializes the ClientConfig structure with sane defaults
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Url: "http://localhost:8080",
	}
}
