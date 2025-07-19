package user

import (
	"context"
	"errors"
	"fmt"
	credstackError "github.com/credstack/credstack-lib/errors"
	userModel "github.com/credstack/credstack-lib/proto/user"
	"github.com/credstack/credstack-lib/server"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongoOpts "go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ErrUserDoesNotExist - Provides a named error for when operations fail due to the user account not existing
var ErrUserDoesNotExist = credstackError.NewError(404, "USER_DOES_NOT_EXIST", "user: user does not exist under the specified email address")

/*
GetUser - Fetches a user from the database and returns it's protobuf model for it. If you are fetching a user
without its credentials, then set withCredentials to false. Projection is used on this field to prevent it from
leaving the database due to its sensitive information
*/
func GetUser(serv *server.Server, email string, withCredentials bool) (*userModel.User, error) {
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

	var ret userModel.User

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
ListUser - Lists all users present in the database. Optionally, a limit can be specified here to limit the
amount of data returned at once. The maximum that can be returned in a single call is 10, and if a limit exceeds this, it
will be reset to 10
*/
func ListUser(serv *server.Server, limit int, withCredentials bool) ([]*userModel.User, error) {
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

	ret := make([]*userModel.User, 0, limit)

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
UpdateUser - Provides functionality for updating a select number of fields of the user model. A valid email address
must be provided as an argument for this function call. Fields to update can be passed in the patch parameter. The
following fields can be updated: Username, GivenName, FamilyName, Gender, BirthDate, and Address. If you need to
update a different field (like email), then use the dedicated functions for this
*/
func UpdateUser(serv *server.Server, email string, patch *userModel.User) error {
	if email == "" {
		return ErrUserMissingIdentifier
	}

	/*
		buildUserPatch - Provides a sub-function to convert the given userModel into a bson.M struct that can be
		provided to mongo.UpdateOne. Only specified fields are supported in this function, so not all are included
		here
	*/
	buildUserPatch := func(patch *userModel.User) bson.M {
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
DeleteUser - Completely removes a user account from CredStack. A valid email address must be passed
in this parameter, or it will return ErrUserMissingIdentifier. If the deleted count returned is equal to
zero, then the function considers the user to not exist. A successful call to this function will return
nil
*/
func DeleteUser(serv *server.Server, email string) error {
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
