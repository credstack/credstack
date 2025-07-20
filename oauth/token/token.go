package token

import (
	"context"
	"errors"
	"fmt"
	credstackError "github.com/credstack/credstack-lib/errors"
	"github.com/credstack/credstack-lib/oauth/jwk"
	"github.com/credstack/credstack-lib/server"
	apiModel "github.com/credstack/credstack-models/proto/api"
	applicationModel "github.com/credstack/credstack-models/proto/application"
	tokenModel "github.com/credstack/credstack-models/proto/token"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ErrFailedToSignToken - An error that gets wrapped when jwt.Token.SignedString returns an error
var ErrFailedToSignToken = credstackError.NewError(500, "ERR_FAILED_TO_SIGN", "token: Failed to sign token due to an internal error")

// ErrTokenCollision - An error that gets returned when a duplicate access token is created. This should realistically never return as JWT access tokens are unique
var ErrTokenCollision = credstackError.NewError(500, "ERR_TOKEN_COLLISION", "token: A duplicate access token was issued")

/*
generateToken - Generates a token based on the Application and API that are passed in the parameter. Claims that are passed
will be inserted into the generated token. Calling this function alone, does not store the tokens in the database and only
generates the token. An instantiated server structure needs to be passed here to ensure that we can fetch the current
active encryption key for token signing (RS256)
*/
func generateToken(serv *server.Server, api *apiModel.API, app *applicationModel.Application, claims jwt.RegisteredClaims) (*tokenModel.Token, error) {
	var token *tokenModel.Token

	switch api.TokenType.String() {
	case "RS256":
		privateKey, err := jwk.GetActiveKey(serv, api.TokenType.String(), api.Audience)
		if err != nil {
			return nil, err
		}

		tok, err := generateRS256(privateKey, claims, uint32(app.TokenLifetime))
		if err != nil {
			return nil, err
		}

		token = tok
	case "HS256":
		tok, err := generateHS256(app.ClientSecret, claims, uint32(app.TokenLifetime))
		if err != nil {
			return nil, err
		}

		token = tok
	}

	if token == nil {
		return nil, fmt.Errorf("%w (%v)", ErrFailedToSignToken, "Invalid Signing Algorithm")
	}

	return token, nil
}

/*
NewToken - Generates a token according to the algorithm provided by the API passed as a parameter. Any tokens generated
with this function are stored in the database, and are automatically converted to a token response.
*/
func NewToken(serv *server.Server, api *apiModel.API, app *applicationModel.Application, claims jwt.RegisteredClaims) (*tokenModel.TokenResponse, error) {
	token, err := generateToken(serv, api, app, claims)
	if err != nil {
		return nil, err
	}

	/*
		Were currently just storing the plain old token response here, which may pose some issues down the road specifically
		if we want to implement functionality for revoking tokens for a specific user. This will fit the token revocation
		endpoint spec as defined in RFC 7009 fairly well though, as we really just need the access token we want to
		revoke here.

		Keep in mind, JWTs are stateless. So "revoking" a token, really just means that the token will not be reported
		as active by the token introspection endpoint
	*/
	_, err = serv.Database().Collection("token").InsertOne(context.Background(), token)
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

	resp := &tokenModel.TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    token.ExpiresIn,
		IdToken:      "",
		RefreshToken: "",
		Scope:        "",
	}

	return resp, nil
}
