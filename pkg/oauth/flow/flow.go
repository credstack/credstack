package flow

import (
	"github.com/credstack/credstack/pkg/api"
	"github.com/credstack/credstack/pkg/application"
	credstackError "github.com/credstack/credstack/pkg/errors"
	applicationModel "github.com/credstack/credstack/pkg/models/application"
	"github.com/credstack/credstack/pkg/models/request"
	tokenModel "github.com/credstack/credstack/pkg/models/token"
	"github.com/credstack/credstack/pkg/server"
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
initiateAuthFlow - Initiate auth flow not only fetches the application and API models from the database based on what was
requested by the caller in request.TokenRequest, but also performs validation on this. initiateAuthFlow performs validation
to ensure that the audience present in the token request is under the applications allowed audiences list. Additionally,
this function ensures that the requested grant type is both authorized and valid.

This function returns a tokenModel.AuthenticationTicket, which provides all the context required for credstack to issue
a token. This primarily includes a pointer to the token request, along with the application and API structures. In future
releases this may include the claims required to be placed within the token as well. This authentication ticket is then
passed the authentication flow handler for the request grant type
*/
func initiateAuthFlow(serv *server.Server, request *request.TokenRequest) (*tokenModel.AuthenticationTicket, error) {
	/*
		Since Application.GrantType is an enum, we need to perform some conversion here to be able to
		validate its string representation of it. Ideally, all of this validation could be externalized
		to the DB layer by updating GetApplication to validate this
	*/
	grantType, ok := applicationModel.GrantTypes_value[request.GrantType]
	if !ok {
		return nil, ErrInvalidGrantType
	}

	app, err := application.GetApplication(serv, request.ClientId, true)
	if err != nil {
		return nil, err
	}

	/*
		We always want to validate that the application model is **permitted** to issue tokens under the
		requested audience. This is done to ensure that the applications and api's the end user creates can
		be granular in their permissions.

		We do all of this validation here, before we request the API to ensure that we are not wasting CPU time by
		making database calls for a potentially invalid request
	*/
	if !slices.Contains(app.AllowedAudiences, request.Audience) {
		return nil, ErrUnauthorizedAudience
	}

	/*
		Just like with the API audience, we validate that the application is allowed to issue tokens under the
		requested grant type
	*/
	if !slices.Contains(app.GrantType, applicationModel.GrantTypes(grantType)) {
		return nil, ErrUnauthorizedGrantType
	}

	userApi, err := api.GetAPI(serv, request.Audience)
	if err != nil {
		return nil, err
	}

	ticket := &tokenModel.AuthenticationTicket{
		Application:  app,
		Api:          userApi,
		TokenRequest: request,
	}

	return ticket, nil
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

	ticket, err := initiateAuthFlow(serv, request)
	if err != nil {
		return nil, err
	}

	switch request.GrantType {
	case "client_credentials":
		resp, err := ClientCredentialsFlow(serv, ticket, issuer)
		if err != nil {
			return nil, err
		}

		return resp, nil
	}

	return nil, ErrInvalidGrantType
}
