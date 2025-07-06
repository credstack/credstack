package oauth

import (
	"github.com/stevezaluk/credstack-lib/api"
	"github.com/stevezaluk/credstack-lib/application"
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	"github.com/stevezaluk/credstack-lib/key"
	"github.com/stevezaluk/credstack-lib/oauth/algorithm"
	"github.com/stevezaluk/credstack-lib/proto/request"
	"github.com/stevezaluk/credstack-lib/proto/response"
	"github.com/stevezaluk/credstack-lib/server"
)

// ErrInvalidTokenRequest - An error that gets returned if one or more elements of the token request are missing
var ErrInvalidTokenRequest = credstackError.NewError(400, "ERR_INVALID_TOKEN_REQ", "token: Failed to issue token. One or more parts of the token request is missing")

// ErrInvalidClientCredentials - An error that gets returned when the client credentials sent in a token request do not match what was received from the database (during client credentials flow)
var ErrInvalidClientCredentials = credstackError.NewError(401, "ERR_INVALID_CLIENT_CREDENTIALS", "token: Unable to issue token. Invalid client credentials were supplied")

/*
IssueToken - A universal function for issuing tokens under any grant type for any audience. This should be used as the token
generating function for implementing OAuth authentication flows. Depending on the authentication flow that is being
used here, some parts of the request.TokenRequest structure that gets passed is mandatory and an ErrInvalidTokenRequest
error will be returned if one is missing.

Additionally, the client_id that is used in the token request is validated to ensure that it is allowed to issue tokens
on behalf of the requested audience. If the client_id is no authorized, then ErrInvalidAudience is passed. Finally, the
application is also validated to ensure that it can issue tokens under the specified OAuth grant type.

TODO: Store tokens in Mongo so that they can be revoked quickly
TODO: Update this function to allow specifying expiration date
TODO: Better abstraction here. This function is getting a bit convoluted (especially when more flows get added)
*/
func IssueToken(serv *server.Server, request *request.TokenRequest, issuer string) (*response.TokenResponse, error) {
	app, err := application.GetApplication(serv, request.ClientId, true)
	if err != nil {
		return nil, err
	}

	err = ValidateTokenRequest(request, app)
	if err != nil {
		return nil, err
	}

	userApi, err := api.GetAPI(serv, request.Audience)
	if err != nil {
		return nil, err
	}

	tokenResp := new(response.TokenResponse)
	if request.GrantType == "client_credentials" {
		tokenClaims := NewClaimsWithSubject(
			issuer,
			userApi.Audience,
			app.ClientId,
		)

		if userApi.TokenType.String() == "RS256" {
			privateKey, err := key.GetActiveKey(serv, userApi.TokenType.String(), userApi.Audience)
			if err != nil {
				return nil, err
			}

			generatedToken, signed, err := algorithm.GenerateRS256(privateKey, tokenClaims)
			if err != nil {
				return nil, err
			}

			resp, err := MarshalTokenResponse(generatedToken, signed)
			if err != nil {
				return nil, err
			}

			tokenResp = resp
		}

		if userApi.TokenType.String() == "HS256" {
			generatedToken, signed, err := algorithm.GenerateHS256(app.ClientSecret, tokenClaims)
			if err != nil {
				return nil, err
			}

			resp, err := MarshalTokenResponse(generatedToken, signed)
			if err != nil {
				return nil, err
			}

			tokenResp = resp
		}
	}

	// not storing tokens here. BAD! need this for quick revocation

	return tokenResp, nil
}
