package internal

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/credstack/credstack/internal/config"
)

// HTTPResource Overarching abstraction that provides common functionality for all HTTP resources
type HTTPResource struct {
	// client The http.Client that gets used for all requests
	client *http.Client

	// config The shared config.ClientConfig structure used for building requests
	config config.ClientConfig
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

// Do Execute an HTTP request while enforcing its retry/backoff policy
func (resource *HTTPResource) Do(req *http.Request, model interface{}) (resp *http.Response, err error) {
	for i := 0; i < resource.config.Retry; i++ {
		resp, err = resource.client.Do(req)
		if err == nil {
			break
		}

		time.Sleep(resource.config.BackoffDuration)
	}

	if resp == nil {
		return nil, errors.New("http: Got errors when making HTTP request to " + resource.config.Url)
	}

	defer resp.Body.Close()

	buf := make([]byte, 256) // this might fuck us over later if a requests exceeds 256 bytes
	_, err = resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}

	err = json.Unmarshal(buf[:], model)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func New(config config.ClientConfig) *HTTPResource {
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			IdleConnTimeout:    30 * time.Second,
			MaxIdleConns:       5,
		},
	}

	return &HTTPResource{
		client: client,
		config: config,
	}
}
