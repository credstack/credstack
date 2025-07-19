package token

import (
	credstackError "github.com/credstack/credstack-lib/errors"
	tokenModel "github.com/credstack/credstack-lib/proto/request"
)

// ErrInvalidTokenRequest - An error that gets returned if one or more elements of the token request are missing
var ErrInvalidTokenRequest = credstackError.NewError(400, "ERR_INVALID_TOKEN_REQ", "token: Failed to issue token. One or more parts of the token request is missing")

/*
ValidateTokenRequest - Initiates token request validation to ensure that tokens can be issued according to the request
that was received.
*/
func ValidateTokenRequest(request *tokenModel.TokenRequest) error {
	
	/*
		Authorization code flow is a bit simpler to validate for, as we only really need to ensure that request.Code and
		request.RedirectUri match. We don't need to explicitly validate the client_id here as application.GetApplication
		would have returned an error if the client did not exist
	*/
	if request.GrantType == "authorization_code" {
		if request.RedirectUri == "" || request.Code == "" {
			return ErrInvalidTokenRequest
		}
	}

	return nil
}
