package user

import (
	"context"
	"errors"
	"fmt"
	credstackError "github.com/credstack/credstack-lib/errors"
	"github.com/credstack/credstack-lib/header"
	"github.com/credstack/credstack-lib/options"
	userModel "github.com/credstack/credstack-lib/proto/user"
	"github.com/credstack/credstack-lib/server"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongoOpts "go.mongodb.org/mongo-driver/v2/mongo/options"
	"regexp"
)

// ErrPasswordTooShort - Provides a named error to be returned when a user-provided password is too short
var ErrPasswordTooShort = credstackError.NewError(400, "CRED_PASS_TOO_SHORT", "credential: password too short")

// ErrPasswordTooLong - Provides a named error to be returned when a user-provided password is too long
var ErrPasswordTooLong = credstackError.NewError(400, "CRED_PASS_TOO_LONG", "credential: password too long")

// ErrUserMissingIdentifier - Provides a named error that gets thrown when you try and create a new user without an Email
var ErrUserMissingIdentifier = credstackError.NewError(400, "USER_MISSING_ID", "user: User is either missing a username or an email address")

// ErrUserAlreadyExists - Provides a named error that occurs when you try and duplicate a user
var ErrUserAlreadyExists = credstackError.NewError(409, "USER_ALREADY_EXISTS", "user: User already exists under the specified email address")

// ErrEmailAddressInvalid - Provides a named error that occurs when the caller attempts to register a user with an improperly formatted email address
var ErrEmailAddressInvalid = credstackError.NewError(400, "EMAIL_ADDRESS_INVALID", "email: Invalid email address")

// emailRegex - A regular expression for validating that an email address is formatted properly
var emailRegex = regexp.MustCompile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")

/*
RegisterUser - Core logic for registering new users with credstack. Performs full validation on any of the user data
provided here. New users must have a unique email address and this will be validated here. Any errors propagated through
this function call is returned. This is generally only named errors defined in this package.
*/
func RegisterUser(serv *server.Server, opts *options.CredentialOptions, email string, username string, password string) error {
	/*
		Originally, I was going to place this logic in NewCredential, however we don't want to consume a DB call
		if the information provided here is invalid (Bad Request)
	*/
	if email == "" || username == "" {
		return ErrUserMissingIdentifier
	}

	if len(password) < int(opts.MinSecretLength) {
		return ErrPasswordTooShort
	}

	if len(password) > int(opts.MaxSecretLength) {
		return ErrPasswordTooLong
	}

	/*
		Here we want to validate that the email address being used is valid. Eventually, we want to send the user a
		validation email on account creation, so this must be valid
	*/
	if !emailRegex.MatchString(email) {
		return ErrEmailAddressInvalid
	}

	/*
		Once we validate that the provided information is correct, we need to ensure that the user does not
		already exist under this email address. Realistically, I wanted to **just** use unique indexes for
		this. However, if we only relied on the write exception that would be produced from the InsertOne
		call, then we would always have to pay Argon Hashing cost even on users that already exist.

		Generally,
		Argon hashing can be **very** slow, and I would rather consume an additional database call then have to
		always pay Argon hashing costs

		The most sane way to accomplish this was to consume an additional DB call, but use projection to avoid
		pulling down the entire model, and use result.Err to avoid having to decode the model as well, as we don't
		care about its results, we only care that we don't get mongo.ErrNoDocuments returned to us
	*/
	result := serv.Database().Collection("user").FindOne(
		context.Background(),
		bson.M{"email": email},
		mongoOpts.FindOne().SetProjection(bson.M{"email": 1}))

	/*
		If our error is mongo.ErrNoDocuments, then we know the user does not exist. If we receive another error,
		then we wrap ErrInternalDatabase and return the error to the caller
	*/
	if result.Err() != nil {
		if !errors.Is(result.Err(), mongo.ErrNoDocuments) && result.Err() != nil {
			return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, result)
		}

		if !errors.Is(result.Err(), mongo.ErrNoDocuments) {
			return ErrUserAlreadyExists
		}
	}

	/*
		Finally, once we know that the user doesn't already exist, we can pay the Argon cost, hash there password,
		and store the results in the collection object
	*/
	credential, err := NewCredential(password, opts)
	if err != nil {
		return err
	}

	/*
		Here we are constructing the user model that will get inserted into MongoDB. We need to use make on roles
		and scopes to ensure that these don't get inserted into MongoDB as null fields. By default, an empty slice
		is also nil in Go-Lang and this is what will get stored in our Database.

		TODO: Validation for email address
	*/
	userHeader := header.NewHeader(email)

	newUser := &userModel.User{
		Header:     userHeader,
		Sub:        userHeader.Identifier,
		Username:   username,
		Email:      email,
		Credential: credential,
		Roles:      make([]string, 0),
		Scopes:     make([]string, 0),
	}

	/*
		We finally get to insert our model into MongoDB. Regardless of our previous FindOne call to validate
		user existence, we still want to check for a write exception and wrap any un-expected errors here
	*/
	_, err = serv.Database().Collection("user").InsertOne(context.Background(), newUser)
	if err != nil {
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
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	return nil
}
