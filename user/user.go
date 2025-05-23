package user

import (
	"context"
	"errors"
	"fmt"
	"github.com/stevezaluk/credstack-lib/server"
	userModel "github.com/stevezaluk/credstack-models/proto/user"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongoOpts "go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ErrUserDoesNotExist -
var ErrUserDoesNotExist = errors.New("user: user does not exist under the specified email address")

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
			return nil, fmt.Errorf("%w %v", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUserDoesNotExist
		}
	}

	return &ret, nil
}
