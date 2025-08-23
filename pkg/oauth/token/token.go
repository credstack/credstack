package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	credstackError "github.com/credstack/credstack/pkg/errors"
	"github.com/credstack/credstack/pkg/server"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ErrFailedToSignToken - An error that gets wrapped when jwt.Token.SignedString returns an error
var ErrFailedToSignToken = credstackError.NewError(500, "ERR_FAILED_TO_SIGN", "token: Failed to sign token due to an internal error")

// ErrTokenCollision - An error that gets returned when a duplicate access token is created. This should realistically never return as JWT access tokens are unique
var ErrTokenCollision = credstackError.NewError(500, "ERR_TOKEN_COLLISION", "token: A duplicate access token was issued")

/*
Token - An internal representation of an issued token. This is generally not displayed to the user, but is instead used
for tracking tokens internally in the database. TokenResponse is instead returned to the user
*/
type Token struct {
	// Subject - The subject the token was issued for. Can be a user id or a client ID
	Subject string `json:"sub" bson:"sub"`

	// ClientId - The client ID of the application that issued the token
	ClientId string `json:"client_id" bson:"client_id"`

	// AccessToken - The access token that was issued
	AccessToken string `json:"access_token" bson:"access_token"`

	// RefreshToken - The refresh token that was issued
	RefreshToken string `json:"refresh_token" bson:"refresh_token"`

	// IdToken - The ID token that was issued
	IdToken string `json:"id_token" bson:"id_token"`

	// ExpiresIn - The time in seconds that the token expires in
	ExpiresIn uint32 `json:"expires_in" bson:"expires_in"`

	// ExpiresAt - A timestamp that represents the datetime in which the access token expires
	ExpiresAt time.Time `json:"expires_at" bson:"expires_at"`

	// RefreshExpiresAt - A timestamp that represents the datetime in which the refresh token expires
	RefreshExpiresAt time.Time `json:"refresh_expires_at" bson:"refresh_expires_at"`

	// Scope - Any permission scopes that were issued with the token
	Scope string `json:"scope" bson:"scope"`
}

/*
NewToken - Provides logic for storing tokens of a specific type in the database. This does not generate tokens as this
logic is provided through a method on the API struct
*/
func NewToken(serv *server.Server, token *Token) error {
	_, err := serv.Database().Collection("token").InsertOne(context.Background(), token)
	if err != nil {
		var writeError mongo.WriteException
		if errors.As(err, &writeError) {
			if writeError.HasErrorCode(11000) { // 11000 is the error code for a WriteError. This should be a const
				return ErrTokenCollision // this should almost never occur, but we check for it regardless
			}
		}

		// always return a wrapped internal database error here
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	return nil
}
