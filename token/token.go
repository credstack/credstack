package token

import (
	"github.com/stevezaluk/credstack-lib/api"
	"github.com/stevezaluk/credstack-lib/application"
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	"github.com/stevezaluk/credstack-lib/key"
	"github.com/stevezaluk/credstack-lib/proto/request"
	"github.com/stevezaluk/credstack-lib/server"
)

// ErrInvalidTokenRequest - An error that gets returned if one or more elements of the token request are missing
var ErrInvalidTokenRequest = credstackError.NewError(400, "ERR_INVALID_TOKEN_REQ", "token: Failed to issue token. One or more parts of the token request is missing")

// ErrInvalidClientCredentials - An error that gets returned when the client credentials sent in a token request do not match what was received from the database (during client credentials flow)
var ErrInvalidClientCredentials = credstackError.NewError(401, "ERR_INVALID_CLIENT_CREDENTIALS", "token: Unable to issue token. Invalid client credentials were supplied")

/*
NewToken - A universal function for issuing tokens under any grant type for any audience. This should be used as the token
generating function for implementing OAuth authentication flows. Depending on the authentication flow that is being
used here, some parts of the request.TokenRequest structure that gets passed is mandatory and an ErrInvalidTokenRequest
error will be returned if one is missing.

Additionally, the client_id that is used in the token request is validated to ensure that it is allowed to issue tokens
on behalf of the requested audience. If the client_id is no authorized, then ErrInvalidAudience is passed. Finally, the
application is also validated to ensure that it can issue tokens under the specified OAuth grant type.

There are currently some **major** drawbacks to this function at the moment. For starters the token request that is passed
as the second argument, is not validated which can cause the function to return early if an empty string is passed as the
client ID. Similarly, if an invalid grant type is passed, the function returns an empty string and multiple database
calls are wasted. The tokens here are not getting stored either which can be a problem for when users want to revoke
there tokens
*/
func NewToken(serv *server.Server, request *request.TokenRequest, issuer string) (string, error) {
	// need to validate the token request here. BAD!
	app, err := application.GetApplication(serv, request.ClientId, true)
	if err != nil {
		return "", err
	}

	userApi, err := api.GetAPI(serv, request.Audience)
	if err != nil {
		return "", err
	}

	tokenStr := ""
	if request.GrantType == "client_credentials" {
		// validate public/confidential here

		// this really needs to be subtle.ConstantTimeCompare
		if request.ClientSecret != app.ClientSecret {
			return "", ErrInvalidClientCredentials
		}

		privateKey, err := key.GetActiveKey(serv, userApi.TokenType.String(), userApi.Audience)
		if err != nil {
			return "", err
		}

		tokenClaims := NewClaimsWithSubject(
			issuer,
			userApi.Audience,
			privateKey.Header.Identifier,
			app.ClientId,
		)

		if userApi.TokenType.String() == "RS256" {
			generated, err := GenerateRS256(privateKey, tokenClaims)
			if err != nil {
				return "", err
			}

			tokenStr = generated
		}
	}

	// not storing tokens here. BAD! need this for quick revocation

	return tokenStr, nil
}
