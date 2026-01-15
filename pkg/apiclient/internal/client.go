package internal

import (
	"net/http"
	"time"
)

// HTTPResource Overarching abstraction that provides common functionality for all HTTP resources
type HTTPResource struct {
	// client The http.Client that gets used for all requests
	client *http.Client
}

func New() *HTTPResource {
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			IdleConnTimeout:    30 * time.Second,
			MaxIdleConns:       5,
		},
	}

	return &HTTPResource{
		client: client,
	}
}
