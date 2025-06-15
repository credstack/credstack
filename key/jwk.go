package key

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
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
GetJWKS - Fetches all JSON Web Keys stored in the database and returns them as a slice. The length of this slice should
really never exceed 2, as key.RotateKeys will remove old keys
*/
func GetJWKS(serv *server.Server) (*key.JSONWebKeySet, error) {
	jwks := new(key.JSONWebKeySet)

	/*
		This function call is actually fairly simple, as all we really need to do here is list out the entire collection.
	*/
	cursor, err := serv.Database().Collection("jwk").Find(context.Background(), bson.M{"kty": "RSA"})
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
GetActiveKey - Fetches the latest active private key from the database according to the algorithm that is provided in the
parameter of this function. If one cannot be found, then ErrKeyNotExist is returned in the error. This shouldn't happen
generally as this gets generated when credstack is started for the first time.

TODO: This does not support HS-256
TODO: This may not be needed, validate as the rest of this package gets fleshed out
*/
func GetActiveKey(serv *server.Server, alg string) (*rsa.PrivateKey, error) {
	var jwk key.PrivateJSONWebKey

	/*
		The header.identifier field always represents our Key Identifiers (kid) so we can always safely lookup our key
		with this. Additionally, the same KID is used across both the JWK and the Private Key to simplify key access
	*/
	result := serv.Database().Collection("key").FindOne(context.Background(), bson.M{"alg": alg, "is_current": true})
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
		Since our key is stored in base64 format in the database, we first must decode our resulting key. We always
		want to return an error here as well if we fail to decode
	*/
	keyBytes := []byte(jwk.KeyMaterial)
	decoded, err := secret.DecodeBase64(keyBytes, uint32(len(keyBytes)))
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", secret.ErrFailedToBaseDecode, err)
	}

	/*
		Our base64 encoded value is stored as PKCS#8 format, so we then want to parse that. The result from this function
		call returns us a general PrivateKey interface, which we then need to cast into our RSA Private Key
	*/
	parsedKey, err := x509.ParsePKCS8PrivateKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrMarshalKey, err)
	}

	/*
		Finally, we want to validate this key as we parsed it from a string, and we want to be confident that it can be
		used for encryption/decryption
	*/
	privateKey := parsedKey.(*rsa.PrivateKey)
	err = privateKey.Validate()
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrKeyIsNotValid, err)
	}

	return privateKey, nil
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
