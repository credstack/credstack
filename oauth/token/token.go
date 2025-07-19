package token

import (
	"context"
	"errors"
	"fmt"
	credstackError "github.com/credstack/credstack-lib/errors"
	"github.com/credstack/credstack-lib/key"
	"github.com/credstack/credstack-lib/oauth/flow"
	apiModel "github.com/credstack/credstack-lib/proto/api"
	applicationModel "github.com/credstack/credstack-lib/proto/application"
	"github.com/credstack/credstack-lib/proto/request"
	tokenModel "github.com/credstack/credstack-lib/proto/token"
	"github.com/credstack/credstack-lib/server"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/mongo"
	pbTimestamp "google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

// ErrFailedToSignToken - An error that gets wrapped when jwt.Token.SignedString returns an error
var ErrFailedToSignToken = credstackError.NewError(500, "ERR_FAILED_TO_SIGN", "token: Failed to sign token due to an internal error")

// ErrTokenCollision - An error that gets returned when a duplicate access token is created. This should realistically never return as JWT access tokens are unique
var ErrTokenCollision = credstackError.NewError(500, "ERR_TOKEN_COLLISION", "token: A duplicate access token was issued")

/*
newToken - Provides a centralized area for token generation to occur. newToken provides the logic required for associating
a token type it's associating handler. If a valid signing algorithm is used, then it will return its formatted token
response, otherwise it will return ErrFailedToSignToken

TODO: We really need a custom model for storing access tokens. A custom expiresAt field is needed for leveraging TTL indexes. This needs to be an actual timestamp, not just seconds until the token expires
*/
func newToken(serv *server.Server, api *apiModel.API, app *applicationModel.Application, claims jwt.RegisteredClaims) (*tokenModel.TokenResponse, error) {
	var tokenResp *tokenModel.TokenResponse

	switch api.TokenType.String() {
	case "RS256":
		privateKey, err := key.GetActiveKey(serv, api.TokenType.String(), api.Audience)
		if err != nil {
			return nil, err
		}

		resp, err := generateRS256(privateKey, claims, uint32(app.TokenLifetime))
		if err != nil {
			return nil, err
		}

		tokenResp = resp
	case "HS256":
		resp, err := generateHS256(app.ClientSecret, claims, uint32(app.TokenLifetime))
		if err != nil {
			return nil, err
		}

		tokenResp = resp
	}

	if tokenResp == nil {
		return nil, fmt.Errorf("%w (%v)", ErrFailedToSignToken, "Invalid Signing Algorithm")
	}

	/*
		We use a separate model here to track tokens internally as we need some additional metadata to properly
		support revocation and introspection

		This isn't working with TTL indexes properly, so for now tokens will pretty much never get removed
		from the database. This is a major limitation here, but without creating some hacky shit it will
		have to exist.
	*/
	internalToken := &tokenModel.Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IdToken:      tokenResp.IdToken,
		ClientId:     app.ClientId,
		ExpiresIn:    tokenResp.ExpiresIn,
		ExpiresAt:    pbTimestamp.New(time.Now().Add(time.Duration(tokenResp.ExpiresIn))),
		Scope:        tokenResp.Scope,
	}

	/*
		Were currently just storing the plain old token response here, which may pose some issues down the road specifically
		if we want to implement functionality for revoking tokens for a specific user. This will fit the token revocation
		endpoint spec as defined in RFC 7009 fairly well though, as we really just need the access token we want to
		revoke here.

		Keep in mind, JWTs are stateless. So "revoking" a token, really just means that the token will not be reported
		as active by the token introspection endpoint
	*/
	_, err := serv.Database().Collection("token").InsertOne(context.Background(), internalToken)
	if err != nil {
		var writeError mongo.WriteException
		if errors.As(err, &writeError) {
			if writeError.HasErrorCode(11000) { // 11000 is the error code for a WriteError. This should be a const
				return nil, ErrTokenCollision // this should almost never occur, but we check for it regardless
			}
		}

		// always return a wrapped internal database error here
		return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	return tokenResp, nil
}

/*
IssueToken - A universal function for issuing tokens under any grant type for any audience. This should be used as the token
generating function for implementing OAuth authentication flows. Depending on the authentication flow that is being
used here, some parts of the request.TokenRequest structure that gets passed is mandatory and an ErrInvalidTokenRequest
error will be returned if one is missing.

Additionally, the client_id that is used in the token request is validated to ensure that it is allowed to issue tokens
on behalf of the requested audience. If the client_id is no authorized, then ErrInvalidAudience is passed. Finally, the
application is also validated to ensure that it can issue tokens under the specified OAuth grant type.
*/
func IssueToken(serv *server.Server, request *request.TokenRequest, issuer string) (*tokenModel.TokenResponse, error) {
	/*
		We always validate that these are not empty strings as these are required parameters for any grant type that is
		used.
	*/
	if request.Audience == "" || request.GrantType == "" {
		return nil, ErrInvalidTokenRequest
	}

	userApi, app, err := flow.InitiateAuthFlow(serv, request.Audience, request.ClientId, request.GrantType)
	if err != nil {
		return nil, err
	}

	switch request.GrantType {
	case "client_credentials":
		claims, err := flow.ClientCredentialsFlow(app, userApi, request, issuer)
		if err != nil {
			return nil, err
		}

		tokenResp, err := newToken(serv, userApi, app, *claims)
		if err != nil {
			return nil, err
		}

		return tokenResp, nil
	}

	return nil, ErrFailedToSignToken
}
