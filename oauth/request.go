package oauth

import (
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	applicationModel "github.com/stevezaluk/credstack-lib/proto/application"
	tokenModel "github.com/stevezaluk/credstack-lib/proto/request"
)

// ErrUnauthorizedAudience - An error that gets returned when an application tries to issue tokens for an audience that it is not authorized too
var ErrUnauthorizedAudience = credstackError.NewError(403, "ERR_UNAUTHORIZED_AUDIENCE", "token: Unable to issue token for the specified audience. Application is not authorized too")

// ErrUnauthorizedGrantType - An error that gets returned when an application tries to issue tokens for a grant type that it is not authorized too
var ErrUnauthorizedGrantType = credstackError.NewError(403, "ERR_UNAUTHORIZED_GRANT_TYPE", "token: Invalid grant type for the specified application")

// ErrVisibilityIssue - An error that gets returned when the caller tries to issue a token for a public application
var ErrVisibilityIssue = credstackError.NewError(400, "ERR_VISIBILITY_ERROR", "token: Failed to issue token for application. Public clients cannot use client credentials flow")

// ErrInvalidTokenRequest - An error that gets returned if one or more elements of the token request are missing
var ErrInvalidTokenRequest = credstackError.NewError(400, "ERR_INVALID_TOKEN_REQ", "token: Failed to issue token. One or more parts of the token request is missing")

// ErrInvalidClientCredentials - An error that gets returned when the client credentials sent in a token request do not match what was received from the database (during client credentials flow)
var ErrInvalidClientCredentials = credstackError.NewError(401, "ERR_INVALID_CLIENT_CREDENTIALS", "token: Unable to issue token. Invalid client credentials were supplied")

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
	/*
		We always validate that these are not empty strings as these are required parameters for any grant type that is
		used
	*/
	if request.Audience == "" || request.GrantType == "" {
		return ErrInvalidTokenRequest
	}

	/*
		Next we validate the Application is authorized to issue tokens for the requested audience, under the
		requested grant type
	*/
	if valid := validateAudience(app, request.Audience); !valid {
		return ErrUnauthorizedAudience
	}

	if valid := validateGrantType(app, request.GrantType); !valid {
		return ErrUnauthorizedGrantType
	}

	/*
		Here want to validate parameters specific to the client_credentials flow. We also want to validate the visibility
		of the application here as public applications are not able to utilize client_credentials flow
	*/
	if request.GrantType == "client_credentials" {
		if app.IsPublic {
			return ErrVisibilityIssue
		}

		/*
			This is kind of un-needed, as the below conditional would fail if this was an empty string, but it creates
			some clarity on the errors that are occurring during the token issuance process
		*/
		if request.ClientId == "" || request.ClientSecret == "" {
			return ErrInvalidTokenRequest
		}

		// this needs to be subtle compare
		if request.ClientSecret != app.ClientSecret {
			return ErrInvalidClientCredentials
		}
	}

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
