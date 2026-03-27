package jwk

import (
	"context"
	"fmt"

	credstackError "github.com/credstack/credstack/sdk/pkg/errors"
	"github.com/credstack/credstack/sdk/pkg/server"
)

var ErrGenerateKey = credstackError.NewError(500, "ERR_GENERATING_KEY", "jwk: Failed to generate cryptographic key")
var ErrMarshalKey = credstackError.NewError(500, "ERR_MARSHALING_KEY", "jwk: Failed to marshal/unmarshal key")
var ErrKeyIsNotValid = credstackError.NewError(500, "ERR_KEY_NOT_VALID", "jwk: The requested private or public key is not valid")

/*
JSONWebKey - Represents a JSON Web Key used for signing tokens
*/
type JSONWebKey struct {
	// Kty - Defines the type of key this JWK represents
	Kty string `json:"kty" bson:"kty"`

	// Use - Defines the use of this JWK, usually sig
	Use string `json:"use" bson:"use"`

	// Kid - The unique identifier of the key
	Kid string `json:"kid" bson:"kid"`

	// Alg - Defines the algorithm that this JWK was generated using
	Alg string `json:"alg" bson:"alg"`

	// N - Public modulos for the key
	N string `json:"n" bson:"n"`

	// E - Public exponent for the key
	E string `json:"e" bson:"e"`
}

/*
New - Generates a new key depending on the algorithm that you specify in the parameter. Calling this function will
immediately set the key as the current one, however this will not retroactively update previously issued key. If you are
attempting to rotate/revoke keys, then you should use RotateKeys or RotateRevokeKeys.

Additionally, this function does not validate that its given audience exists, before it issues a key for it.

TODO: Update alg to use protobuf enum
TODO: Update this to remove alg check. HS256 tokens use client secret for signing
*/
func New(serv *server.Server, alg string, audience string) (*PrivateJSONWebKey, error) {
	ret := new(PrivateJSONWebKey)
	if alg == "RS256" {
		privateKey, jwk, err := NewPrivateKey(audience)
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
