package application

import (
	"context"
	"errors"
	"fmt"
	credstackError "github.com/credstack/credstack/pkg/errors"
	"github.com/credstack/credstack/pkg/header"
	applicationModel "github.com/credstack/credstack/pkg/models/application"
	"github.com/credstack/credstack/pkg/secret"
	"github.com/credstack/credstack/pkg/server"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongoOpts "go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ErrInvalidClientCredentials - An error that gets returned when the client credentials sent in a token request do not match what was received from the database (during client credentials flow)
var ErrInvalidClientCredentials = credstackError.NewError(401, "ERR_INVALID_CLIENT_CREDENTIALS", "token: Unable to issue token. Invalid client credentials were supplied")

// ErrVisibilityIssue - An error that gets returned when the caller tries to issue a token for a public application
var ErrVisibilityIssue = credstackError.NewError(400, "ERR_VISIBILITY_ERROR", "token: Failed to issue token for application. Public clients cannot use client credentials flow")

// ErrClientIDCollision - Provides a named error for when a new application is created with the same client ID
var ErrClientIDCollision = credstackError.NewError(500, "APP_CLIENT_ID_COLLISION", "application: A collision was detected while creating a new application")

// ErrAppMissingIdentifier - Provides a named error for when you try and fetch an application with no client id
var ErrAppMissingIdentifier = credstackError.NewError(400, "APP_MISSING_ID", "application: Application is missing a Client ID")

// ErrAppDoesNotExist - Provides a named error for when you try and fetch an application that does not exist
var ErrAppDoesNotExist = credstackError.NewError(404, "APP_DOES_NOT_EXIST", "application: Application does not exist under the specified client ID")

/*
NewApplication - Creates a new application with the provided grant types in the parameter. If an empty slice is provided
here, then the Authorization Code grant type is appended to the slice as we always want a way to authenticate users.
This is the preferred authentication method as well, as we don't need to directly touch secrets (aside from the auth code)
to be able to authenticate the user.

A single database call is consumed here to be able to insert the data into Mongo. If the same client ID is generated as
an existing application, then the error: ErrClientIDCollision is returned. Additionally, we wrap any errors that are
encountered here and returned.
*/
func NewApplication(serv *server.Server, name string, isPublic bool, grantTypes ...applicationModel.GrantTypes) (string, error) {
	/*
		If we get a grant types slice that has a length of zero, we always want to append the Authorization Code grant
		type to it. This ensures that we always have a form of authentication available
	*/
	if len(grantTypes) == 0 {
		grantTypes = append(grantTypes, applicationModel.GrantTypes_authorization_code)
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
	newApplication := &applicationModel.Application{
		Header:           header.NewHeader(clientId),
		Name:             name,
		IsPublic:         isPublic,
		GrantType:        grantTypes,
		RedirectUri:      "",
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
	_, err = serv.Database().Collection("application").InsertOne(context.Background(), newApplication)
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
ListApplication - Lists all applications present in the database. Optionally, a limit can be specified here to limit the
amount of data returned at once. The maximum that can be returned in a single call is 10, and if a limit exceeds this, it
will be reset to 10
*/
func ListApplication(serv *server.Server, limit int, withCredentials bool) ([]*applicationModel.Application, error) {
	if limit > 10 {
		limit = 10
	}

	findOpts := mongoOpts.Find().SetLimit(int64(limit))
	if !withCredentials {
		findOpts = findOpts.SetProjection(bson.M{"client_secret": 0})
	}

	result, err := serv.Database().Collection("application").Find(
		context.Background(),
		bson.M{},
		findOpts,
	)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	ret := make([]*applicationModel.Application, 0, limit)

	err = result.All(context.Background(), &ret)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrAppDoesNotExist
		}
	}

	return ret, nil
}

/*
GetApplication - Fetches an application from the database and returns is protobuf model. If you are fetching an app without
its credentials, then set withCredentials to false. Projection is used on this to prevent the credentials from even leaving
the database. If the app does not exist under the client_id, then ErrAppDoesNotExist is returned. If you try and fetch
an application with an empty client_id, then ErrAppMissingIdentifier is returned.
*/
func GetApplication(serv *server.Server, clientId string, withCredentials bool) (*applicationModel.Application, error) {
	if clientId == "" {
		return nil, ErrAppMissingIdentifier
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
	result := serv.Database().Collection("application").FindOne(
		context.Background(),
		bson.M{"client_id": clientId},
		findOpts,
	)

	var ret applicationModel.Application

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
			return nil, ErrAppDoesNotExist
		}
	}

	return &ret, nil
}

/*
UpdateApplication - Provides functionality for updating a select number of fields of the app model. A valid client id
must be provided as an argument for this function call. Fields to update can be passed in the patch parameter. The
following fields can be updated: RedirectURI, TokenLifetime, GrantType.
*/
func UpdateApplication(serv *server.Server, clientId string, patch *applicationModel.Application) error {
	if clientId == "" {
		return ErrAppMissingIdentifier
	}

	/*
		buildAppPatch - Provides a sub-function to convert the given appModel into a bson.M struct that can be
		provided to mongo.UpdateOne. Only specified fields are supported in this function, so not all are included
		here
	*/
	buildAppPatch := func(patch *applicationModel.Application) bson.M {
		update := make(bson.M)

		if patch.Name != "" {
			update["name"] = patch.Name
		}

		if patch.IsPublic {
			update["is_public"] = patch.IsPublic
		}

		if patch.RedirectUri != "" {
			update["redirect_uri"] = patch.RedirectUri
		}

		if patch.TokenLifetime != 0 {
			update["token_lifetime"] = patch.TokenLifetime
		}

		if len(patch.GrantType) != 0 {
			update["grant_type"] = patch.GrantType
		}

		if len(patch.AllowedAudiences) != 0 {
			update["allowed_audiences"] = patch.AllowedAudiences
		}

		return update
	}

	result, err := serv.Database().Collection("application").UpdateOne(
		context.Background(),
		bson.M{"client_id": clientId},
		bson.M{"$set": buildAppPatch(patch)},
	)

	if err != nil {
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	if result.MatchedCount == 0 {
		return ErrAppDoesNotExist
	}

	return nil
}

/*
DeleteApplication - Completely removes an application from CredStack. A valid client ID must be passed
in this parameter, or it will return ErrAppMissingIdentifier. If the deleted count returned is equal to
zero, then the function considers the user to not exist. A successful call to this function will return
nil
*/
func DeleteApplication(serv *server.Server, clientId string) error {
	if clientId == "" {
		return ErrAppMissingIdentifier
	}

	result, err := serv.Database().Collection("application").DeleteOne(
		context.Background(),
		bson.M{"client_id": clientId},
	)

	if err != nil {
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	if result.DeletedCount == 0 {
		return ErrAppDoesNotExist
	}

	return nil
}
