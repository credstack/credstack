package internal

import (
	"net/http"
	"runtime"
	"time"
)

// HTTPResource Overarching abstraction that provides common functionality for all HTTP resources
type HTTPResource struct {
	// client The http.Client that gets used for all requests
	client *http.Client
}

// BuildRequest Builds a request based with headers inserted for identification and authorization
func (resource *HTTPResource) BuildRequest(method string, uri string) (*http.Request, error) {
	req, err := http.NewRequest(method, uri, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "credstack-api-client/1.0 ("+runtime.GOOS+") ("+runtime.GOARCH+")")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return req, nil
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
