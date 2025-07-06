package token

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stevezaluk/credstack-lib/api"
	"github.com/stevezaluk/credstack-lib/application"
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	"github.com/stevezaluk/credstack-lib/key"
	"github.com/stevezaluk/credstack-lib/proto/request"
	"github.com/stevezaluk/credstack-lib/proto/response"
	"github.com/stevezaluk/credstack-lib/server"
)

// ErrInvalidTokenRequest - An error that gets returned if one or more elements of the token request are missing
var ErrInvalidTokenRequest = credstackError.NewError(400, "ERR_INVALID_TOKEN_REQ", "token: Failed to issue token. One or more parts of the token request is missing")

// ErrInvalidClientCredentials - An error that gets returned when the client credentials sent in a token request do not match what was received from the database (during client credentials flow)
var ErrInvalidClientCredentials = credstackError.NewError(401, "ERR_INVALID_CLIENT_CREDENTIALS", "token: Unable to issue token. Invalid client credentials were supplied")

// ErrFailedToSignToken - An error that gets wrapped when jwt.Token.SignedString returns an error
var ErrFailedToSignToken = credstackError.NewError(500, "ERR_FAILED_TO_SIGN", "token: Failed to sign token due to an internal error")

/*
tokenToResponse - Converts jwt.Token structures into response.TokenResponse structures so that they can be returned
effectively

TODO: Need support for id tokens and refresh tokens here
TODO: Expires in is not rendering properly, showing expiration instead of token lifetime
*/
func tokenToResponse(token *jwt.Token, signedString string) (*response.TokenResponse, error) {
	expirationDate, err := token.Claims.GetExpirationTime()
	if err != nil {
		// wrapping this error with ErrFailedToSignToken is not ideal as it can lead to some confusion on
		// how this function failed but... oh well!
		return nil, fmt.Errorf("%w (%v)", ErrFailedToSignToken, err)
	}
	/*
		After we actually sign our token, we can quickly convert it back into a response.TokenResponse structure so that
		it can be returned from the API
	*/
	signedResponse := &response.TokenResponse{
		AccessToken:  signedString,
		TokenType:    "Bearer",
		ExpiresIn:    uint32(expirationDate.Time.Unix()), // this is bad, could lose precision by down converting to uint32
		RefreshToken: "",
		IdToken:      "",
		Scope:        "",
	}

	return signedResponse, nil
}

/*
NewToken - A universal function for issuing tokens under any grant type for any audience. This should be used as the token
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
func NewToken(serv *server.Server, request *request.TokenRequest, issuer string) (*response.TokenResponse, error) {
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

			generatedToken, signed, err := GenerateRS256(privateKey, tokenClaims)
			if err != nil {
				return nil, err
			}

			resp, err := tokenToResponse(generatedToken, signed)
			if err != nil {
				return nil, err
			}

			tokenResp = resp
		}

		if userApi.TokenType.String() == "HS256" {
			generatedToken, signed, err := GenerateHS256(app.ClientSecret, tokenClaims)
			if err != nil {
				return nil, err
			}

			resp, err := tokenToResponse(generatedToken, signed)
			if err != nil {
				return nil, err
			}

			tokenResp = resp
		}
	}

	// not storing tokens here. BAD! need this for quick revocation

	return tokenResp, nil
}
