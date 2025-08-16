package user

import (
	"context"
	"errors"
	"fmt"

	credstackError "github.com/credstack/credstack/pkg/errors"
	"github.com/credstack/credstack/pkg/models/header"
	"github.com/credstack/credstack/pkg/server"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongoOpts "go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ErrUserDoesNotExist - Provides a named error for when operations fail due to the user account not existing
var ErrUserDoesNotExist = credstackError.NewError(404, "USER_DOES_NOT_EXIST", "user: user does not exist under the specified email address")

type User struct {
	// Header - The header for the User. Created at object birth
	Header *header.Header `json:"header" bson:"header"`

	// Username - The username for the user. Required at registration but does not need to be unique
	Username string `json:"username" bson:"username"`

	// Email - The email for the user. Required at registration and must be unique
	Email string `json:"email" bson:"email"`

	// EmailVerified - A boolean variable for determining if the user has validated there email address
	EmailVerified bool `json:"email_verified" bson:"email_verified"`

	// GiveName - The first name for the user
	GivenName string `json:"given_name" bson:"given_name"`

	// MiddleName - The middle name for the user
	MiddleName string `json:"middle_name" bson:"middle_name"`

	// FamilyName - The last name for the user
	FamilyName string `json:"family_name" bson:"family_name"`

	// Gender - The self-assigned gender for the user
	Gender string `json:"gender" bson:"gender"`

	// BirthDate - The birthdate for the user
	BirthDate string `json:"birth_date" bson:"birth_date"`

	// ZoneInfo - The timezone that the user resides in
	ZoneInfo string `json:"zone_info" bson:"zone_info"`

	// PhoneNumber - The user's phone number. Can be used for 2FA
	PhoneNumber string `json:"phone_number" bson:"phone_number"`

	// PhoneNumberVerified - A boolean variable for determining if the user has validated there phone number
	PhoneNumberVerified bool `json:"phone_number_verified" bson:"phone_number_verified"`

	// Address - The user's physical address which includes street name, town/city, state and country
	Address string `json:"address" bson:"address"`

	// Credential - The structure containing the users hashed password (and its parameters)
	Credential *Credential `json:"credential" bson:"credential"`

	// Scopes - A string slice containing scopes that have been directly assigned to the user
	Scopes []string `json:"scopes" bson:"scopes"`

	// Roles - A string slice containing roles that have been assigned to the user
	Roles []string `json:"roles" bson:"roles"`
}

/*
Get - Fetches a user from the database and returns it's protobuf model for it. If you are fetching a user
without its credentials, then set withCredentials to false. Projection is used on this field to prevent it from
leaving the database due to its sensitive information
*/
func Get(serv *server.Server, email string, withCredentials bool) (*User, error) {
	if email == "" {
		return nil, ErrUserMissingIdentifier
	}

	/*
		We always use projection here to ensure that the credential field does not even
		leave the database. If it is not needed, then we don't want to even touch it
	*/
	findOpts := mongoOpts.FindOne()
	if !withCredentials {
		findOpts = findOpts.SetProjection(bson.M{"credential": 0})
	}

	/*
		We always pass **some** find options here, but defaults are used if the caller
		does not set withCredentials to false
	*/
	result := serv.Database().Collection("user").FindOne(
		context.Background(),
		bson.M{"email": email},
		findOpts,
	)

	var ret User

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
			return nil, ErrUserDoesNotExist
		}
	}

	return &ret, nil
}

/*
List - Lists all users present in the database. Optionally, a limit can be specified here to limit the
amount of data returned at once. The maximum that can be returned in a single call is 10, and if a limit exceeds this, it
will be reset to 10
*/
func List(serv *server.Server, limit int, withCredentials bool) ([]*User, error) {
	if limit > 10 {
		limit = 10
	}

	findOpts := mongoOpts.Find().SetBatchSize(int32(limit))
	if !withCredentials {
		findOpts.SetProjection(bson.M{"credential": 0})
	}

	result, err := serv.Database().Collection("user").Find(
		context.Background(),
		bson.M{},
		findOpts,
	)

	if err != nil {
		return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	ret := make([]*User, 0, limit)

	err = result.All(context.Background(), &ret)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUserDoesNotExist
		}
	}

	return ret, nil
}

/*
Update - Provides functionality for updating a select number of fields of the user model. A valid email address
must be provided as an argument for this function call. Fields to update can be passed in the patch parameter. The
following fields can be updated: Username, GivenName, FamilyName, Gender, BirthDate, and Address. If you need to
update a different field (like email), then use the dedicated functions for this
*/
func Update(serv *server.Server, email string, patch *User) error {
	if email == "" {
		return ErrUserMissingIdentifier
	}

	/*
		buildUserPatch - Provides a sub-function to convert the given userModel into a bson.M struct that can be
		provided to mongo.UpdateOne. Only specified fields are supported in this function, so not all are included
		here
	*/
	buildUserPatch := func(patch *User) bson.M {
		update := make(bson.M)

		if patch.Username != "" {
			update["username"] = patch.Username
		}

		if patch.GivenName != "" {
			update["given_name"] = patch.GivenName
		}

		if patch.FamilyName != "" {
			update["family_name"] = patch.FamilyName
		}

		if patch.Gender != "" {
			update["gender"] = patch.Gender
		}

		if patch.BirthDate != "" {
			update["birth_date"] = patch.BirthDate
		}

		if patch.Address != "" {
			update["address"] = patch.Address
		}

		return update
	}

	result, err := serv.Database().Collection("user").UpdateOne(
		context.Background(),
		bson.M{"email": email},
		bson.M{"$set": buildUserPatch(patch)},
	)

	if err != nil {
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	if result.MatchedCount == 0 {
		return ErrUserDoesNotExist
	}

	return nil
}

/*
Delete - Completely removes a user account from CredStack. A valid email address must be passed
in this parameter, or it will return ErrUserMissingIdentifier. If the deleted count returned is equal to
zero, then the function considers the user to not exist. A successful call to this function will return
nil
*/
func Delete(serv *server.Server, email string) error {
	if email == "" {
		return ErrUserMissingIdentifier
	}

	result, err := serv.Database().Collection("user").DeleteOne(
		context.Background(),
		bson.M{"email": email},
	)

	if err != nil {
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	if result.DeletedCount == 0 {
		return ErrUserDoesNotExist
	}

	return nil
}
