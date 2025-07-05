package token

import (
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	applicationModel "github.com/stevezaluk/credstack-lib/proto/application"
	tokenModel "github.com/stevezaluk/credstack-lib/proto/request"
)

// ErrUnauthorizedAudience - An error that gets returned when an application tries to issue tokens for an audience that it is not authorized too
var ErrUnauthorizedAudience = credstackError.NewError(403, "ERR_UNAUTHORIZED_AUDIENCE", "token: Unable to issue token for the specified audience. Application is not authorized too")

// ErrUnauthorizedGrantType - An error that gets returned when an application tries to issue tokens for a grant type that it is not authorized too
var ErrUnauthorizedGrantType = credstackError.NewError(403, "ERR_UNAUTHORIZED_GRANT_TYPE", "token: Invalid grant type for the specified application")

/*
validateAudience - Validates that an application is allowed to issue tokens for a specified audience. Returns true if it
is allowed, returns false otherwise. If a nil application is provided in the first argument, then false is also returned
*/
func validateAudience(app *applicationModel.Application, audience string) bool {
	if app == nil {
		return false
	}

	for _, aud := range app.AllowedAudiences {
		if audience == aud {
			return true
		}
	}

	return false
}

/*
validateGrantType - Validates that an application is allowed to issue tokens for a specific grant type. Returns true if it
is allowed, returns false otherwise. If a nil application is provided in the first argument, then false is also returned
*/
func validateGrantType(app *applicationModel.Application, grant string) bool {
	if app == nil {
		return false
	}

	grantType, ok := applicationModel.GrantTypes_value[grant]
	if !ok {
		return false
	}

	convertedGrantType := applicationModel.GrantTypes(grantType)

	for _, compare := range app.GrantType {
		if compare == convertedGrantType {
			return true
		}
	}

	return false
}

/*
ValidateTokenRequest - Initiates token request validation to ensure that tokens can be issued according to the request
that was received.
*/
func ValidateTokenRequest(request *tokenModel.TokenRequest, app *applicationModel.Application) error {
	if request.Audience == "" || request.GrantType == "" {
		return ErrInvalidTokenRequest
	}

	if valid := validateAudience(app, request.Audience); !valid {
		return ErrUnauthorizedAudience
	}

	if valid := validateGrantType(app, request.GrantType); !valid {
		return ErrUnauthorizedGrantType
	}

	if request.GrantType == "client_credentials" {
		if request.ClientId == "" || request.ClientSecret == "" {
			return ErrInvalidTokenRequest
		}

		// this needs to be subtle compare
		if request.ClientSecret != app.ClientSecret {
			return ErrInvalidClientCredentials
		}
	}

	// need validation for auth code + PKCE

	return nil
}
