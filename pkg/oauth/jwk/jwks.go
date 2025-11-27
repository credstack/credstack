package jwk

import (
	"context"
	"errors"
	"fmt"

	"github.com/credstack/credstack/internal/server"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

/*
JSONWebKeySet - Represents a list of public keys that can be used for validating token signatures
*/
type JSONWebKeySet struct {
	// Keys - All Keys available for signing under the set
	Keys []JSONWebKey `json:"keys" bson:"keys"`
}

/*
JWKS - Fetches all JSON Web Keys stored in the database and returns them as a slice. Only RSA Keys are returned with
this function call, as this is intended to be used with the .well-known/jwks.json endpoint, and HSA secrets should not
be exposed publicly as they are symmetrical

TODO: Maybe rethink this to return only keys by a specific audience
*/
func JWKS(serv *server.Server) (*JSONWebKeySet, error) {
	jwks := new(JSONWebKeySet)

	/*
		This function call is actually fairly simple, as all we really need to do here is list out the entire collection.
	*/
	cursor, err := serv.Database().Collection("jwk").Find(context.Background(), bson.M{"kty": "RSA"})
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}
	}

	/*
		Then we simply just decode all the results into our slice and then return it.
	*/
	err = cursor.All(context.Background(), &jwks.Keys) // check here for proper errors
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrKeyNotExist
		}
	}

	return jwks, nil
}
