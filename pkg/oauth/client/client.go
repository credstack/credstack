package client

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"

	"github.com/credstack/credstack/internal/server"
	credstackError "github.com/credstack/credstack/pkg/errors"
	"github.com/credstack/credstack/pkg/header"
	"github.com/credstack/credstack/pkg/models/request"
	"github.com/credstack/credstack/pkg/oauth/claim"
	"github.com/credstack/credstack/pkg/secret"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongoOpts "go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	// GrantTypeClientCredentials - A constant string representing the client credentials grant type
	GrantTypeClientCredentials string = "client_credentials"

	// GrantTypeAuthorizationCode - A constant string representing the authorization code grant type
	GrantTypeAuthorizationCode string = "authorization_code"

	// GrantTypeRefreshToken - A constant string representing the refresh token grant type
	GrantTypeRefreshToken string = "refresh_token"

	// GrantTypePassword - A constant string representing the deprecated password grant type
	GrantTypePassword string = "password"
)

// GrantTypes - All possible grant types that a caller can use for creating new applications
var GrantTypes = []string{GrantTypeClientCredentials, GrantTypeAuthorizationCode, GrantTypeRefreshToken, GrantTypePassword}

// ErrInvalidClientCredentials - An error that gets returned when the client credentials sent in a token request do not match what was received from the database (during client credentials flow)
var ErrInvalidClientCredentials = credstackError.NewError(401, "ERR_INVALID_CLIENT_CREDENTIALS", "token: Unable to issue token. Invalid client credentials were supplied")

// ErrVisibilityIssue - An error that gets returned when the caller tries to issue a token for a public application
var ErrVisibilityIssue = credstackError.NewError(400, "ERR_VISIBILITY_ERROR", "token: Failed to issue token for application. Public clients cannot use client credentials flow")

// ErrClientIDCollision - Provides a named error for when a new application is created with the same client ID
var ErrClientIDCollision = credstackError.NewError(500, "CLIENT_ID_COLLISION", "oauth_client: A collision was detected while creating a new application")

// ErrClientMissingIdentifier - Provides a named error for when you try and fetch an application with no client id
var ErrClientMissingIdentifier = credstackError.NewError(400, "CLIENT_MISSING_ID", "oauth_client: Client is missing a Client ID")

// ErrClientDoesNotExist - Provides a named error for when you try and fetch an application that does not exist
var ErrClientDoesNotExist = credstackError.NewError(404, "CLIENT_DOES_NOT_EXIST", "oauth_client: Client does not exist under the specified client ID")

// ErrUnauthorizedGrantType - An error that gets returned when an application tries to issue tokens for a grant type that it is not authorized too
var ErrUnauthorizedGrantType = credstackError.NewError(403, "ERR_UNAUTHORIZED_GRANT_TYPE", "token: Invalid grant type for the specified application")

// ErrUnauthorizedAudience - An error that gets returned when an application tries to issue tokens for an audience that it is not authorized too
var ErrUnauthorizedAudience = credstackError.NewError(403, "ERR_UNAUTHORIZED_AUDIENCE", "token: Unable to issue token for the specified audience. Application is not authorized too")

/*
Client - Represents the OAuth client that wants to issue tokens for an API
*/
type Client struct {
	// Header - The header for the Client. Created at object birth
	Header *header.Header `json:"header" bson:"header"`

	// Name - The name of the Client as defined by the user
	Name string `bson:"name" json:"name"`

	// IsPublic - Determines if the Client is public. If this is set to true, then the Client cannot ue Client Credentials Flow
	IsPublic bool `bson:"is_public" json:"is_public"`

	// ClientId - The client ID for the Client. Gets generated at birth
	ClientId string `bson:"client_id" json:"client_id"`

	// ClientSecret - The client secret for the Client. Gets generated at birth
	ClientSecret string `bson:"client_secret" json:"client_secret"`

	// RedirectURI - The redirect URI for post-authentication. Defined by the user
	RedirectURI string `bson:"redirect_uri" json:"redirect_uri"`

	// TokenLifetime - An unsigned integer representing the amount of time in seconds that the token is valid for
	TokenLifetime uint64 `bson:"token_lifetime" json:"token_lifetime"`

	// GrantTypes - The grant types that the Client is allowed to issue tokens under
	GrantTypes []string `bson:"grant_types" json:"grant_types"`

	// AllowedAudiences - A string slice representing which ResourceServers are allowed to issue tokens for this Client
	AllowedAudiences []string `bson:"allowed_audiences" json:"allowed_audiences"`
}

/*
ValidateAuthFlow - Ensures that the application is authorized to return an authentication token based on the provided
token request. A 'nil' return value indicates success
*/
func (client *Client) ValidateAuthFlow(request *request.TokenRequest) error {
	if !slices.Contains(client.GrantTypes, request.GrantType) {
		return ErrUnauthorizedGrantType
	}

	if !slices.Contains(client.AllowedAudiences, request.Audience) {
		return ErrUnauthorizedAudience
	}

	return nil
}

/*
ClientCredentials - Attempts to issue a token under Client Credentials flow and begins any validation required for
ensuring that the request received was valid.

TODO: When tenant's are implemented, issuer needs to be removed as a parameter here
*/
func (client *Client) ClientCredentials(request *request.TokenRequest, issuer string) (*jwt.RegisteredClaims, error) {
	if client.IsPublic {
		return nil, ErrVisibilityIssue
	}

	/*
		We use subtle.ConstantTimeCompare here to ensure that we are protected from side channel attacks on the
		server itself. Ideally, any credential validation that requires a direct comparison would use ConstantTimeCompare.

		Any value returned by this function other than 1, indicates a failure
	*/
	if subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(request.ClientSecret)) != 1 {
		return nil, ErrInvalidClientCredentials
	}

	claims := claim.NewClaimsWithSubject(
		issuer,
		request.Audience, // this might cause issues later; this should really be pulled from the API model so that the user doesn't have to use it in the request
		client.ClientId,
		client.TokenLifetime,
	)

	return &claims, nil
}

/*
New - Creates a new application with the provided grant types in the parameter. If an empty slice is provided
here, then the Authorization Code grant type is appended to the slice as we always want a way to authenticate users.
This is the preferred authentication method as well, as we don't need to directly touch secrets (aside from the auth code)
to be able to authenticate the user.

A single database call is consumed here to be able to insert the data into Mongo. If the same client ID is generated as
an existing application, then the error: ErrClientIDCollision is returned. Additionally, we wrap any errors that are
encountered here and returned.
*/
func New(serv *server.Server, name string, isPublic bool, grantTypes ...string) (string, error) {
	/*
		If we get a grant types slice that has a length of zero, we always want to append the Authorization Code grant
		type to it. This ensures that we always have a form of authentication available
	*/
	if len(grantTypes) == 0 {
		grantTypes = append(grantTypes, GrantTypeAuthorizationCode)
	}

	/*
		This is pretty shit code, but I am strapped for time right now and want to get this finished
	*/
	for _, grantType := range grantTypes {
		if !slices.Contains(GrantTypes, grantType) {
			return "", ErrUnauthorizedGrantType
		}
	}

	/*
		Similar to the hashing functions we have, we always generate our secrets first to ensure that we can catch
		any errors before we consume a DB call. The client ID for an application is a simple base64 encoded string
		that is generated using cryptographically secure bytes
	*/
	clientId, err := secret.RandString(16)
	if err != nil {
		return "", err // named error here
	}

	/*
		Just like client_id, the client secret is a base64 encoded string that is generated with cryptographically
		secure bytes. We increase the length here to 128 as we want to provide a great deal of entropy as this is
		effectively a password for the application (for client credentials flow)
	*/
	clientSecret, err := secret.RandString(96)
	if err != nil {
		return "", err // named error here
	}

	/*
		Finally, we build our application.Application model. We are utilizing the client ID as the basis for our header
		as we want to provide the user a way to get this identifier, without needing to make a call to the DB

		TODO: URL Validation for redirect URI
	*/
	newApplication := &Client{
		Header:           header.New(clientId),
		Name:             name,
		IsPublic:         isPublic,
		GrantTypes:       grantTypes,
		RedirectURI:      "",
		TokenLifetime:    86400,
		ClientId:         clientId,
		ClientSecret:     clientSecret,
		AllowedAudiences: []string{},
	}

	/*
		After we build our model, we can consume a single database call to insert our new model. We have unique indexes
		created on both the client ID and header.Identifier fields. Realistically, this should **never** be returned
		as the client ID used is cryptographically secure. Nonetheless, we want to check for the error regardless
	*/
	_, err = serv.Database().Collection("client").InsertOne(context.Background(), newApplication)
	if err != nil {
		var writeError mongo.WriteException
		if errors.As(err, &writeError) {
			if writeError.HasErrorCode(11000) { // this code should probably be passed as a const from Database
				return "", ErrClientIDCollision
			}
		}

		/*
			If we don't get a write exception than some other error occurred, and we can just wrap the
			InternalDatabaseError and return it
		*/
		return "", fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	return clientId, nil
}

/*
List - Lists all applications present in the database. Optionally, a limit can be specified here to limit the
amount of data returned at once. The maximum that can be returned in a single call is 10, and if a limit exceeds this, it
will be reset to 10
*/
func List(serv *server.Server, limit int, withCredentials bool) ([]*Client, error) {
	if limit > 10 {
		limit = 10
	}

	findOpts := mongoOpts.Find().SetLimit(int64(limit))
	if !withCredentials {
		findOpts = findOpts.SetProjection(bson.M{"client_secret": 0})
	}

	result, err := serv.Database().Collection("client").Find(
		context.Background(),
		bson.M{},
		findOpts,
	)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	ret := make([]*Client, 0, limit)

	err = result.All(context.Background(), &ret)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrClientDoesNotExist
		}
	}

	return ret, nil
}

/*
Get - Fetches an application from the database and returns is protobuf model. If you are fetching an app without
its credentials, then set withCredentials to false. Projection is used on this to prevent the credentials from even leaving
the database. If the app does not exist under the client_id, then ErrAppDoesNotExist is returned. If you try and fetch
an application with an empty client_id, then ErrAppMissingIdentifier is returned.
*/
func Get(serv *server.Server, clientId string, withCredentials bool) (*Client, error) {
	if clientId == "" {
		return nil, ErrClientMissingIdentifier
	}
	/*
		We always use projection here to ensure that the credential field does not even
		leave the database. If it is not needed, then we don't want to even touch it
	*/
	findOpts := mongoOpts.FindOne()
	if !withCredentials {
		findOpts = findOpts.SetProjection(bson.M{"client_secret": 0})
	}

	/*
		We always pass **some** find options here, but defaults are used if the caller
		does not set withCredentials to false
	*/
	result := serv.Database().Collection("client").FindOne(
		context.Background(),
		bson.M{"client_id": clientId},
		findOpts,
	)

	var ret Client

	/*
		Finally, we decode our results into our model. We also validate any errors we get here
		as we want to ensure that, if we get no documents, we returned a named error for this
	*/
	err := result.Decode(&ret)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrClientDoesNotExist
		}
	}

	return &ret, nil
}

/*
Update - Provides functionality for updating a select number of fields of the app model. A valid client id
must be provided as an argument for this function call. Fields to update can be passed in the patch parameter. The
following fields can be updated: RedirectURI, TokenLifetime, GrantType.
*/
func Update(serv *server.Server, clientId string, patch *Client) error {
	if clientId == "" {
		return ErrClientMissingIdentifier
	}

	/*
		buildAppPatch - Provides a sub-function to convert the given appModel into a bson.M struct that can be
		provided to mongo.UpdateOne. Only specified fields are supported in this function, so not all are included
		here
	*/
	buildAppPatch := func(patch *Client) bson.M {
		update := make(bson.M)

		if patch.Name != "" {
			update["name"] = patch.Name
		}

		if patch.IsPublic {
			update["is_public"] = patch.IsPublic
		}

		if patch.RedirectURI != "" {
			update["redirect_uri"] = patch.RedirectURI
		}

		if patch.TokenLifetime != 0 {
			update["token_lifetime"] = patch.TokenLifetime
		}

		if len(patch.GrantTypes) != 0 {
			update["grant_type"] = patch.GrantTypes
		}

		if len(patch.AllowedAudiences) != 0 {
			update["allowed_audiences"] = patch.AllowedAudiences
		}

		return update
	}

	result, err := serv.Database().Collection("client").UpdateOne(
		context.Background(),
		bson.M{"client_id": clientId},
		bson.M{"$set": buildAppPatch(patch)},
	)

	if err != nil {
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	if result.MatchedCount == 0 {
		return ErrClientDoesNotExist
	}

	return nil
}

/*
Delete - Completely removes an application from CredStack. A valid client ID must be passed
in this parameter, or it will return ErrAppMissingIdentifier. If the deleted count returned is equal to
zero, then the function considers the user to not exist. A successful call to this function will return
nil
*/
func Delete(serv *server.Server, clientId string) error {
	if clientId == "" {
		return ErrClientMissingIdentifier
	}

	result, err := serv.Database().Collection("client").DeleteOne(
		context.Background(),
		bson.M{"client_id": clientId},
	)

	if err != nil {
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	if result.DeletedCount == 0 {
		return ErrClientDoesNotExist
	}

	return nil
}
