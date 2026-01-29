package jwk

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/credstack/credstack/sdk/internal/server"
	credstackError "github.com/credstack/credstack/sdk/pkg/errors"
	"github.com/credstack/credstack/sdk/pkg/secret"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var ErrGenerateKey = credstackError.NewError(500, "ERR_GENERATING_KEY", "jwk: Failed to generate cryptographic key")
var ErrMarshalKey = credstackError.NewError(500, "ERR_MARSHALING_KEY", "jwk: Failed to marshal/unmarshal key")
var ErrKeyNotExist = credstackError.NewError(404, "ERR_PRIV_KEY_NOT_EXIST", "jwk: Failed to find private key with the requested key ID")
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
RSA - Converts a public JSON Web Key into a rsa.PublicKey struct so that it can be used with the crypto/rsa
package. Any errors in this function are returned wrapped
*/
func (key *JSONWebKey) RSA() (*rsa.PublicKey, error) {
	/*
		We always store our public exponent and modulus as base64 encoded strings to preserve there precision so we
		must decode them before we can use them
	*/
	modulusBytes := []byte(key.N)
	decodedModulus, err := secret.DecodeBase64(modulusBytes, uint32(len(modulusBytes)))
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", secret.ErrFailedToBaseDecode, err)
	}

	exponentBytes := []byte(key.E)
	decodedExponent, err := secret.DecodeBase64(exponentBytes, uint32(len(exponentBytes)))
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", secret.ErrFailedToBaseDecode, err)
	}

	/*
		Then, once they are decoded, we have to convert them back to their respective types

		Since the decoded exponent here is a big-endian byte array, we need to perform some bit shifting magic to be
		able to convert this properly. Using strconv on a string representation of this won't work directly, and you
		would get a parse error. Instead, we can shift each byte of the array by 8 bits (1-byte) and then add them
		together to get our public exponent back
	*/
	modulus := new(big.Int).SetBytes(decodedModulus)
	exponent := 0
	for _, b := range decodedExponent {
		exponent = (exponent << 8) + int(b)
	}

	/*
		Finally, we can add them to the public key model and return them to the caller
	*/
	publicKey := rsa.PublicKey{
		N: modulus,
		E: exponent,
	}

	return &publicKey, nil
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

/*
Get - Fetches the public JSON Web Key that matches the key identifier passed in the parameter. This just returns
the model and other functions provided in this package can be used to convert it back to a valid rsa.PublicKey
*/
func Get(serv *server.Server, kid string) (*JSONWebKey, error) {
	var jwk JSONWebKey

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
ActiveKey - Fetches the latest active private key according to the algorithm that is passed in the parameter. The same
model (key.PrivateJSONWebKey) is used for both RS256 and HS256 keys, so the same function can be used for either. Additional
functions are provided within the package to convert this model into a valid RSA private key to use

TODO: This does not support HS-256
TODO: This may not be needed, validate as the rest of this package gets fleshed out
*/
func ActiveKey(serv *server.Server, alg string, audience string) (*PrivateJSONWebKey, error) {
	var jwk PrivateJSONWebKey

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
