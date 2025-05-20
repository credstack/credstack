package user

import (
	"context"
	"errors"
	"fmt"
	"github.com/stevezaluk/credstack-lib/header"
	"github.com/stevezaluk/credstack-lib/server"
	"github.com/stevezaluk/credstack-models/proto/user"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ErrUserAlreadyExists - Provides a named error that occurs when you try and duplicate a user
var ErrUserAlreadyExists = errors.New("user: User already exists")

// ErrUserMissingIdentifier - Provides a named error that gets thrown when you try and create a new user without an Email
var ErrUserMissingIdentifier = errors.New("user: User is either missing an identifier or an email address")

/*
NewUser - Provides a simple wrapper around a MongoDB query to insert a new user into the database. This performs no
credential generation or validation so you should really use RegisterUser for this. Any header.Identifier that was
passed here will be overwritten, and generated from the email address of the user. A user email address is immutable
so it provides a good basis for identifier.

Any errors that occur here will be returned in the form of named errors. A nil return type indicates that the
call was successful
*/
func NewUser(ctx *server.Server, user *user.User) error {
	if user.Email == "" {
		return ErrUserMissingIdentifier
	}

	user.Header = header.NewHeader(user.Email)

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
