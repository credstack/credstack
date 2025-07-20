package jwk

import (
	"context"
	"errors"
	"fmt"
	credstackError "github.com/credstack/credstack-lib/errors"
	"github.com/credstack/credstack-lib/server"
	jwkModel "github.com/credstack/credstack-models/proto/jwk"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var ErrGenerateKey = credstackError.NewError(500, "ERR_GENERATING_KEY", "jwk: Failed to generate cryptographic key")
var ErrMarshalKey = credstackError.NewError(500, "ERR_MARSHALING_KEY", "jwk: Failed to marshal/unmarshal key")
var ErrKeyNotExist = credstackError.NewError(404, "ERR_PRIV_KEY_NOT_EXIST", "jwk: Failed to find private key with the requested key ID")
var ErrKeyIsNotValid = credstackError.NewError(500, "ERR_KEY_NOT_VALID", "jwk: The requested private or public key is not valid")

/*
GetJWKS - Fetches all JSON Web Keys stored in the database and returns them as a slice. Only RSA Keys are returned with
this function call, as this is intended to be used with the .well-known/jwks.json endpoint, and HSA secrets should not
be exposed publicly as they are symmetrical

TODO: Maybe rethink this to return only keys by a specific audience
*/
func GetJWKS(serv *server.Server) (*jwkModel.JSONWebKeySet, error) {
	jwks := new(jwkModel.JSONWebKeySet)

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

/*
GetJWK - Fetches the public JSON Web Key that matches the key identifier passed in the parameter. This just returns
the model and other functions provided in this package can be used to convert it back to a valid rsa.PublicKey
*/
func GetJWK(serv *server.Server, kid string) (*jwkModel.JSONWebKey, error) {
	var jwk jwkModel.JSONWebKey

	/*
		The header.identifier field always represents our Key Identifiers (kid) so we can always safely lookup our key
		with this. Additionally, the same KID is used across both the JWK and the Private Key to simplify key access
	*/
	result := serv.Database().Collection("jwk").FindOne(context.Background(), bson.M{"kid": kid})
	err := result.Decode(&jwk)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrKeyNotExist
		}
	}

	return &jwk, nil
}

/*
GetActiveKey - Fetches the latest active private key according to the algorithm that is passed in the parameter. The same
model (key.PrivateJSONWebKey) is used for both RS256 and HS256 keys, so the same function can be used for either. Additional
functions are provided within the package to convert this model into a valid RSA private key to use

TODO: This does not support HS-256
TODO: This may not be needed, validate as the rest of this package gets fleshed out
*/
func GetActiveKey(serv *server.Server, alg string, audience string) (*jwkModel.PrivateJSONWebKey, error) {
	var jwk jwkModel.PrivateJSONWebKey

	/*
		The header.identifier field always represents our Key Identifiers (kid) so we can always safely lookup our key
		with this. Additionally, the same KID is used across both the JWK and the Private Key to simplify key access
	*/
	result := serv.Database().Collection("key").FindOne(context.Background(), bson.M{"alg": alg, "is_current": true, "audience": audience})
	err := result.Decode(&jwk)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrKeyNotExist
		}
	}

	return &jwk, nil
}

/*
NewKey - Generates a new key depending on the algorithm that you specify in the parameter. Calling this function will
immediately set the key as the current one, however this will not retroactively update previously issued key. If you are
attempting to rotate/revoke keys, then you should use RotateKeys or RotateRevokeKeys.

Additionally, this function does not validate that its given audience exists, before it issues a key for it.

TODO: Update alg to use protobuf enum
TODO: Update this to remove alg check. HS256 tokens use client secret for signing
*/
func NewKey(serv *server.Server, alg string, audience string) (*jwkModel.PrivateJSONWebKey, error) {
	ret := new(jwkModel.PrivateJSONWebKey)
	if alg == "RS256" {
		privateKey, jwk, err := GenerateRSAKey(audience)
		if err != nil {
			return nil, err
		}

		_, err = serv.Database().Collection("key").InsertOne(context.Background(), privateKey)
		if err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		_, err = serv.Database().Collection("jwk").InsertOne(context.Background(), jwk)
		if err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		ret = privateKey
	}

	return ret, nil
}
