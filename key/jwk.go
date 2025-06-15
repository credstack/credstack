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
GetPrivateKey - Fetches a private key from the database and un-marshals its PKCS#8 key material. The subsequently parsed
key is then validated for mathematical correctness before being returns. The private key returned from this function is
returned as nil if any errors have occured here.

TODO: This does not support HS-256
TODO: This may not be needed, validate as the rest of this package gets fleshed out
*/
func GetPrivateKey(serv *server.Server, kid string) (*rsa.PrivateKey, error) {
	var jwk key.PrivateJSONWebKey

	/*
		The header.identifier field always represents our Key Identifiers (kid) so we can always safely lookup our key
		with this. Additionally, the same KID is used across both the JWK and the Private Key to simplify key access
	*/
	result := serv.Database().Collection("key").FindOne(context.Background(), bson.M{"header.identifier": kid})
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
		Our base64 encoded value is stored as PCKS#8 format, so we then want to parse that. The result from this function
		call returns us a general PrivateKey interface, which we then need to cast into our RSA Private Key
	*/
	parsedKey, err := x509.ParsePKCS8PrivateKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrMarshalKey, err)
	}

	/*
		Finally, we want to validate this key as we parsed it from a string and we want to be confident that it can be
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

/*
RotateJWKS - Rotates the JSON Web Key Set that tokens are being signed with. Any RS256 tokens that were issued previously
with these key's will become invalid after this function call as there previously generated keys can not be used to validate
them.

This function is **very** slow, so executing it should be treated with care. On each call to this function 2 new RSA key's
are generated and then converted into properly formatted JWK's. We want to store these in separate collections so that
we don't need to convert private keys to public keys on each call to .wellknown/jwks.json. This winds up dragging
execution time on this function as we now need to clear our both collections after key generation, and then re-insert
them. 4 total database calls are consumed in this function.

Thankfully, the poor performance on this function should not be incredibly impactful, as this only gets called in two
scenarios: When credstack starts for the first time, and when the user requests a key rotation

TODO: The implementation for this is broken. Start with only one key and then during rotation, add an additional one
TODO: This does not support HS-256
*/
func RotateJWKS(serv *server.Server) error {
	/*
		We are using traditional arrays here over slices as we can always guarantee that the same number of keys are going
		to be generated with this function. This helps us reduce some memory allocations, as every call to append forces
		us to resize the array to accompany for the additional element
	*/
	privateKeys := make([]*key.PrivateJSONWebKey, 2)
	jwks := make([]*key.JSONWebKey, 2)

	/*
		Ideally, this could be exposed to the user to allow them to select how many keys they want to include in a JWKS.
		However, we hard code this value here as increasing the amount of keys in the JWKS slows down key selection
		during token generation
	*/
	for i := 0; i < 2; i++ {
		privateKey, jwk, err := GenerateKey()
		if err != nil {
			return fmt.Errorf("%w (%v)", ErrGenerateKey, err)
		}

		/*
			To account for storing each of them in different collections, we need to different slices here for this as
			well.
		*/
		privateKeys[i] = privateKey
		jwks[i] = jwk
	}

	/*
		To ensure that old keys don't get retained, we want to completely clear out both collections here. We want to
		do this **after** key generation in the event that key generation fails for whatever reason. If we clear out the
		collections before key generation and generation fails, then we are left fucked without any new keys and our
		old ones gone
	*/
	for _, collection := range []string{"key", "jwk"} {
		_, err := serv.Database().Collection(collection).DeleteMany(context.Background(), bson.D{})
		if err != nil {
			return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}
	}

	/*
		After we have our collections cleared out, we can move forward and insert our keys accordingly
	*/
	_, err := serv.Database().Collection("key").InsertMany(context.Background(), privateKeys)
	if err != nil {
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	_, err = serv.Database().Collection("jwk").InsertMany(context.Background(), jwks)
	if err != nil {
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	return nil
}
