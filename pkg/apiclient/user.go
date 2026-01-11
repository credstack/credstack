package apiclient

import "net/http"

// userClient Encapsulates all code required for interacting with the user service
type userClient struct {
	client *http.Client
}

// newUserClient Initializes a new client for interacting with the user service
func newUserClient(client *http.Client) *userClient {
	return &userClient{
		client: client,
	}
}
