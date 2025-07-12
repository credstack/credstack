package token

import (
	"crypto/subtle"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	"github.com/stevezaluk/credstack-lib/key"
	"github.com/stevezaluk/credstack-lib/oauth/flow"
	apiModel "github.com/stevezaluk/credstack-lib/proto/api"
	applicationModel "github.com/stevezaluk/credstack-lib/proto/application"
	"github.com/stevezaluk/credstack-lib/proto/request"
	"github.com/stevezaluk/credstack-lib/proto/response"
	"github.com/stevezaluk/credstack-lib/server"
)

// ErrFailedToSignToken - An error that gets wrapped when jwt.Token.SignedString returns an error
var ErrFailedToSignToken = credstackError.NewError(500, "ERR_FAILED_TO_SIGN", "token: Failed to sign token due to an internal error")

/*
newToken - Provides a centralized area for token generation to occur. newToken provides the logic required for associating
a token type it's associating handler. If a valid signing algorithm is used, then it will return its formatted token
response, otherwise it will return ErrFailedToSignToken

TODO: Store tokens in Mongo so that they can be revoked quickly
*/
func newToken(serv *server.Server, api *apiModel.API, app *applicationModel.Application, claims jwt.RegisteredClaims) (*response.TokenResponse, error) {
	switch api.TokenType.String() {
	case "RS256":
		/*
			We always use the first element in the audience slice as CredStack does not allow issuing multiple audiences
			in tokens
		*/
		privateKey, err := key.GetActiveKey(serv, api.TokenType.String(), api.Audience)
		if err != nil {
			return nil, err
		}

		resp, err := generateRS256(privateKey, claims)
		if err != nil {
			return nil, err
		}

		return resp, nil
	case "HS256":
		resp, err := generateHS256(app.ClientSecret, claims)
		if err != nil {
			return nil, err
		}

		return resp, nil
	}

	return nil, fmt.Errorf("%w (%v)", ErrFailedToSignToken, "Invalid Signing Algorithm")
}

/*
IssueToken - A universal function for issuing tokens under any grant type for any audience. This should be used as the token
generating function for implementing OAuth authentication flows. Depending on the authentication flow that is being
used here, some parts of the request.TokenRequest structure that gets passed is mandatory and an ErrInvalidTokenRequest
error will be returned if one is missing.

Additionally, the client_id that is used in the token request is validated to ensure that it is allowed to issue tokens
on behalf of the requested audience. If the client_id is no authorized, then ErrInvalidAudience is passed. Finally, the
application is also validated to ensure that it can issue tokens under the specified OAuth grant type.

TODO: Update this function to allow specifying expiration date
*/
func IssueToken(serv *server.Server, request *request.TokenRequest, issuer string) (*response.TokenResponse, error) {
	err := ValidateTokenRequest(request)
	if err != nil {
		return nil, err
	}

	userApi, app, err := flow.InitiateAuthFlow(serv, request.Audience, request.ClientId, request.GrantType)
	if err != nil {
		return nil, err
	}

	switch request.GrantType {
	case "client_credentials":
		/*
			Only confidential applications are able to issue tokens under client credentials flow. Similar to our credentials
			validation, we do this before anything else as we can't proceed with the token generation if this is true
		*/
		if app.IsPublic {
			return nil, ErrVisibilityIssue
		}

		/*
			We use subtle.ConstantTimeCompare here to ensure that we are protected from side channel attacks on the
			server itself. Ideally, any credential validation that requires a direct comparison would use ConstantTimeCompare.

			Any value returned by this function other than 1, indicates a failure
		*/
		if subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(request.ClientSecret)) != 1 {
			return nil, ErrInvalidClientCredentials
		}

		tokenClaims := NewClaimsWithSubject(
			issuer,
			userApi.Audience,
			app.ClientId,
		)

		tokenResp, err := newToken(serv, userApi, app, tokenClaims)
		if err != nil {
			return nil, err
		}

		return tokenResp, nil
	}

	return nil, ErrFailedToSignToken
}
