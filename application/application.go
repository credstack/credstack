package application

import (
	"context"
	"errors"
	"fmt"
	"github.com/stevezaluk/credstack-lib/header"
	"github.com/stevezaluk/credstack-lib/internal"
	"github.com/stevezaluk/credstack-lib/secret"
	"github.com/stevezaluk/credstack-lib/server"
	"github.com/stevezaluk/credstack-models/proto/application"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ErrClientIDCollision - Provides a named error for when a new application is created with the same client ID
var ErrClientIDCollision = internal.NewError(500, "APP_CLIENT_ID_COLLISION", "application: A collision was detected while creating a new application")

/*
NewApplication - Creates a new application with the provided grant types in the parameter. If an empty slice is provided
here, then the Authorization Code grant type is appended to the slice as we always want a way to authenticate users.
This is the preferred authentication method as well, as we don't need to directly touch secrets (aside from the auth code)
to be able to authenticate the user.

A single database call is consumed here to be able to insert the data into Mongo. If the same client ID is generated as
an existing application, then the error: ErrClientIDCollision is returned. Additionally, we wrap any errors that are
encountered here and returned.
*/
func NewApplication(serv *server.Server, grantTypes []application.GrantTypes) error {
	/*
		If we get a grant types slice that has a length of zero, we always want to append the Authorization Code grant
		type to it. This ensures that we always have a form of authentication available
	*/
	if len(grantTypes) == 0 {
		grantTypes = append(grantTypes, application.GrantTypes_authorization_code)
	}

	/*
		Similar to the hashing functions we have, we always generate our secrets first to ensure that we can catch
		any errors before we consume a DB call. The client ID for an application is a simple base64 encoded string
		that is generated using cryptographically secure bytes
	*/
	clientId, err := secret.RandString(16)
	if err != nil {
		return err // named error here
	}

	/*
		Just like client_id, the client secret is a base64 encoded string that is generated with cryptographically
		secure bytes. We increase the length here to 128 as we want to provide a great deal of entropy as this is
		effectively a password for the application (for client credentials flow)
	*/
	clientSecret, err := secret.RandString(96)
	if err != nil {
		return err // named error here
	}

	/*
		Finally, we build our application.Application model. We are utilizing the client ID as the basis for our header
		as we want to provide the user a way to get this identifier, without needing to make a call to the DB

		TODO: URL Validation for redirect URI
	*/
	newApplication := &application.Application{
		Header:        header.NewHeader(clientId),
		GrantType:     grantTypes,
		RedirectUri:   "",
		TokenLifetime: 86400,
		ClientId:      clientId,
		ClientSecret:  clientSecret,
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
				return ErrClientIDCollision
			}
		}

		/*
			If we don't get a write exception than some other error occurred, and we can just wrap the
			InternalDatabaseError and return it
		*/
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	return nil
}
