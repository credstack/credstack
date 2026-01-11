package apiclient

import (
	"net/http"
	"time"

	"github.com/credstack/credstack/internal/config"
)

type ApiClient struct {
	// config The ClientConfig for the API client
	config config.ClientConfig

	// client The http.Client that gets used for all requests
	client *http.Client
}

// New Initialize a new credstack API client
func New(config config.ClientConfig) *ApiClient {
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			IdleConnTimeout:    30 * time.Second,
			MaxIdleConns:       5,
		},
	}

	return &ApiClient{
		config: config,
		client: client,
	}
}
