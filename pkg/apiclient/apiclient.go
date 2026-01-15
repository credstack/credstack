package apiclient

import (
	"github.com/credstack/credstack/internal/config"
)

type ApiClient struct {
	// config The ClientConfig for the API client
	config config.ClientConfig
}

// New Initialize a new credstack API client
func New(config config.ClientConfig) *ApiClient {
	return &ApiClient{
		config: config,
	}
}
