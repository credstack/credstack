package key

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	"github.com/stevezaluk/credstack-lib/proto/key"
	"github.com/stevezaluk/credstack-lib/secret"
	"github.com/stevezaluk/credstack-lib/server"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"math/big"
)

var ErrGenerateKey = credstackError.NewError(500, "ERR_GENERATING_KEY", "jwk: Failed to generate cryptographic key")
var ErrMarshalKey = credstackError.NewError(500, "ERR_MARSHALING_KEY", "jwk: Failed to marshal/unmarshal key")
var ErrKeyNotExist = credstackError.NewError(404, "ERR_PRIV_KEY_NOT_EXIST", "jwk: Failed to find private key with the requested key ID")
var ErrKeyIsNotValid = credstackError.NewError(500, "ERR_KEY_NOT_VALID", "jwk: The requested private or public key is not valid")

/*
GetJWKS - Fetches all JSON Web Keys stored in the database and returns them as a slice. Only RSA Keys are returned with
this function call, as this is intended to be used with the .well-known/jwks.json endpoint, and HSA secrets should not
be exposed publicly as they are symmetrical
*/
func GetJWKS(serv *server.Server, audience string) (*key.JSONWebKeySet, error) {
	jwks := new(key.JSONWebKeySet)

	/*
		This function call is actually fairly simple, as all we really need to do here is list out the entire collection.
	*/
	cursor, err := serv.Database().Collection("jwk").Find(context.Background(), bson.M{"kty": "RSA", "audience": audience})
	if err != nil {
		fmt.Println("error during find", err)
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}
	}

	/*
		Then we simply just decode all the results into our slice and then return it.
	*/
	err = cursor.All(context.Background(), &jwks.Keys) // check here for proper errors
	if err != nil {
		fmt.Println("error during cursor decode", err)
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
GetActiveKey - Fetches the latest active private key according to the algorithm that is passed in the parameter. The same
model (key.PrivateJSONWebKey) is used for both RS256 and HS256 keys, so the same function can be used for either. Additional
functions are provided within the package to convert this model into a valid RSA private key to use

TODO: This does not support HS-256
TODO: This may not be needed, validate as the rest of this package gets fleshed out
*/
func GetActiveKey(serv *server.Server, alg string, audience string) (*key.PrivateJSONWebKey, error) {
	var jwk key.PrivateJSONWebKey

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
GetPublicKey - Looks up a JWK by its Key Identifier and parses it back into a rsa.PublicKey for use in token generation.
*/
func GetPublicKey(serv *server.Server, kid string) (*rsa.PublicKey, error) {
	var jwk key.JSONWebKey

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

	/*
		We always store our public exponent and modulus as base64 encoded strings to preserve there precision so we
		must decode them before we can use them
	*/
	modulusBytes := []byte(jwk.N)
	decodedModulus, err := secret.DecodeBase64(modulusBytes, uint32(len(modulusBytes)))
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", secret.ErrFailedToBaseDecode, err)
	}

	exponentBytes := []byte(jwk.E)
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
