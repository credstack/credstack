package flow

import (
	"github.com/credstack/credstack-lib/api"
	"github.com/credstack/credstack-lib/application"
	credstackError "github.com/credstack/credstack-lib/errors"
	"github.com/credstack/credstack-lib/oauth/token"
	apiModel "github.com/credstack/credstack-lib/proto/api"
	applicationModel "github.com/credstack/credstack-lib/proto/application"
	"github.com/credstack/credstack-lib/proto/request"
	tokenModel "github.com/credstack/credstack-lib/proto/token"
	"github.com/credstack/credstack-lib/server"
	"slices"
)

// ErrUnauthorizedAudience - An error that gets returned when an application tries to issue tokens for an audience that it is not authorized too
var ErrUnauthorizedAudience = credstackError.NewError(403, "ERR_UNAUTHORIZED_AUDIENCE", "token: Unable to issue token for the specified audience. Application is not authorized too")

// ErrUnauthorizedGrantType - An error that gets returned when an application tries to issue tokens for a grant type that it is not authorized too
var ErrUnauthorizedGrantType = credstackError.NewError(403, "ERR_UNAUTHORIZED_GRANT_TYPE", "token: Invalid grant type for the specified application")

// ErrInvalidGrantType - A named error that gets returned when an unrecognized grant type is used to attempt to issue tokens
var ErrInvalidGrantType = credstackError.NewError(400, "ERR_INVALID_GRANT", "token: Failed to issue token. The specified grant type does not exist")

// ErrInvalidTokenRequest - An error that gets returned if one or more elements of the token request are missing
var ErrInvalidTokenRequest = credstackError.NewError(400, "ERR_INVALID_TOKEN_REQ", "token: Failed to issue token. One or more parts of the token request is missing")

/*
InitiateAuthFlow - Fetch's an API based on its audience along with its associating application. This acts as a central
"initialization" function for any OAuth authentication flows as we almost always need these two models. Additionally,
some validation is performed here to ensure that the requested application is allowed to issue tokens for the requested
*/
func InitiateAuthFlow(serv *server.Server, audience string, clientId string, requestedGrant string) (*apiModel.API, *applicationModel.Application, error) {
	app, err := application.GetApplication(serv, clientId, true)
	if err != nil {
		return nil, nil, err
	}

	/*
		We always want to validate that the application model is **permitted** to issue tokens under the
		requested audience. This is done to ensure that the applications and api's the end user creates can
		be granular in their permissions.

		We do all of this validation here, before we request the API to ensure that we are not wasting CPU time by
		making database calls for a potentially invalid request
	*/
	if !slices.Contains(app.AllowedAudiences, audience) {
		return nil, nil, ErrUnauthorizedAudience
	}

	/*
		Since Application.GrantType is an enum, we need to perform some conversion here to be able to
		validate its string representation of it. Ideally, all of this validation could be externalized
		to the DB layer by updating GetApplication to validate this
	*/
	grantType, ok := applicationModel.GrantTypes_value[requestedGrant]
	if !ok {
		return nil, nil, ErrInvalidGrantType
	}

	/*
		Just like with the API audience, we validate that the application is allowed to issue tokens under the
		requested grant type
	*/
	if !slices.Contains(app.GrantType, applicationModel.GrantTypes(grantType)) {
		return nil, nil, ErrUnauthorizedGrantType
	}

	userApi, err := api.GetAPI(serv, audience)
	if err != nil {
		return nil, nil, err
	}

	return userApi, app, nil
}

/*
IssueTokenForFlow - Responsible for issuing access tokens under a specific OAuth authentication flow. Handles validating
token requests and marshaling access tokens to a token.TokenResponse structure. Any errors that are returned from this
function are wrapped with errors.CredstackError.
*/
func IssueTokenForFlow(serv *server.Server, request *request.TokenRequest, issuer string) (*tokenModel.TokenResponse, error) {
	if request.Audience == "" || request.GrantType == "" {
		return nil, ErrInvalidTokenRequest
	}

	userApi, app, err := InitiateAuthFlow(serv, request.Audience, request.ClientId, request.GrantType)
	if err != nil {
		return nil, err
	}

	switch request.GrantType {
	case "client_credentials":
		claims, err := ClientCredentialsFlow(app, userApi, request, issuer)
		if err != nil {
			return nil, err
		}

		tokenResp, err := token.NewToken(serv, userApi, app, *claims)
		if err != nil {
			return nil, err
		}

		return tokenResp, nil
	}

	return nil, ErrInvalidGrantType
}
