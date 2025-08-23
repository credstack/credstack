package flow

import (
	credstackError "github.com/credstack/credstack/pkg/errors"
	"github.com/credstack/credstack/pkg/models/request"
	"github.com/credstack/credstack/pkg/models/response"
	"github.com/credstack/credstack/pkg/oauth/api"
	"github.com/credstack/credstack/pkg/oauth/application"
	"github.com/credstack/credstack/pkg/oauth/token"
	"github.com/credstack/credstack/pkg/server"
	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidGrantType - A named error that gets returned when an unrecognized grant type is used to attempt to issue tokens
var ErrInvalidGrantType = credstackError.NewError(400, "ERR_INVALID_GRANT", "token: Failed to issue token. The specified grant type does not exist")

// ErrInvalidTokenRequest - An error that gets returned if one or more elements of the token request are missing
var ErrInvalidTokenRequest = credstackError.NewError(400, "ERR_INVALID_TOKEN_REQ", "token: Failed to issue token. One or more parts of the token request is missing")

/*
IssueTokenForFlow - Responsible for issuing access tokens under a specific OAuth authentication flow. Handles validating
token requests and marshaling access tokens to a token.TokenResponse structure. Any errors that are returned from this
function are wrapped with errors.CredstackError.
*/
func IssueTokenForFlow(serv *server.Server, request *request.TokenRequest, issuer string) (*response.TokenResponse, error) {
	/*
		This should change so that the user doesn't have to use an audience to issue tokens
	*/
	if request.Audience == "" || request.GrantType == "" {
		return nil, ErrInvalidTokenRequest
	}

	app, err := application.Get(serv, request.ClientId, true)
	if err != nil {
		return nil, err
	}

	var claims *jwt.RegisteredClaims

	switch request.GrantType {
	case application.GrantTypeClientCredentials:
		claims, err = app.ClientCredentials(request, issuer)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrInvalidGrantType
	}

	requestedApi, err := api.Get(serv, request.Audience)
	if err != nil {
		return nil, err
	}

	resp, err := token.NewToken(serv, requestedApi, *claims)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
