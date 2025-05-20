package user

import (
	"context"
	"errors"
	"fmt"
	"github.com/stevezaluk/credstack-lib/server"
	"github.com/stevezaluk/credstack-models/proto/user"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ErrUserAlreadyExists - Provides a named error that occurs when you try and duplicate a user
var ErrUserAlreadyExists = errors.New("user: User already exists")

// ErrUserMissingIdentifier - Provides a named error that gets thrown when you try and create a new user without an Email
var ErrUserMissingIdentifier = errors.New("user: User is either missing an identifier or an email address")

/*
NewUser - Provides a simple wrapper around collection.InsertOne to insert newly created users into the database. No
validation or header generation is provided here so you should really use RegisterUser here if you want to create
a new user. Only use this function if you have a pre-generated user struct that you want to implement

This function, similar to others in service packages expect that you have unique indexes built around collections
as this won't make an additional database call to validate that the user exists. This only checks for a write exception
upon making an InsertOne call. See the doc's for more information on where/how indexes should be created.
*/
func NewUser(ctx *server.Server, user *user.User) error {
	_, err := ctx.Database().Collection("user").InsertOne(context.Background(), user)
	if err != nil {
		/*
			Here instead of consuming an additional database to validate if the user exists, we can
			actually just check for a write exception. This is where unique indexes become especially
			useful, and should be created. server.Database.Init can be used to create these for you
		*/
		var writeError mongo.WriteException
		if errors.As(err, &writeError) {
			if writeError.HasErrorCode(11000) { // this code should probably be passed as a const from Database
				return ErrUserAlreadyExists
			}
		}

		/*
			If we don't get a write exception than some other error occurred, and we can just wrap the
			InternalDatabaseError and return it
		*/
		return fmt.Errorf("%w %v", server.ErrInternalDatabase, err)
	}

	return nil
}
