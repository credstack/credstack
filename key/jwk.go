package key

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	"github.com/stevezaluk/credstack-lib/proto/key"
	"github.com/stevezaluk/credstack-lib/secret"
	"github.com/stevezaluk/credstack-lib/server"
	"go.mongodb.org/mongo-driver/v2/bson"
	"math/big"
)

var ErrGenerateKey = credstackError.NewError(500, "ERR_GENERATING_KEY", "jwk: Failed to generate cryptographic key")
var ErrMarshalKey = credstackError.NewError(500, "ERR_MARSHALING_KEY", "jwk: Failed to marshal/unmarshal key")

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

/*
ToJWK - Extracts the public key from an RSA Private Key and converts it to the JWK model
*/
func ToJWK(keyPair *key.PrivateJSONWebKey) (*key.JSONWebKey, error) {
	keyBytes := []byte(keyPair.KeyMaterial)

	/*
		Since we are encoding our marshalled key, we first must decode it. The error returned from DecodeBase64
		is already a wrapped error, so we don't need to do any additional wrapping here
	*/
	decoded, err := secret.DecodeBase64(keyBytes, uint32(len(keyBytes)))
	if err != nil {
		return nil, err
	}

	/*
		Then, once we have it decoded, we can immediately parse it from PKCS#8
	*/
	parsedKey, err := x509.ParsePKCS8PrivateKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("%v (%w)", ErrMarshalKey, err)
	}

	/*
		We always need to cast the value returned from x509.ParsePKCS8PrivateKey as this returns an interface
		not a direct pointer
	*/
	privateKey := parsedKey.(*rsa.PrivateKey)

	/*
		Finally, we convert it to key.JSONWebKey. We encode our modulus as these are big.Int values,
		and we need to preserve precision as protobuf does not provide a way of storing big.Int's

		This is a bit hacky here with the way we are converting our public exponent. This should probably be changed
		to an integer in the protobuf model
	*/
	jwk := &key.JSONWebKey{
		Use: "sig",
		Kty: "RSA",
		Alg: "RS256",
		Kid: keyPair.Header.Identifier,
		N:   secret.EncodeBase64(privateKey.PublicKey.N.Bytes()),
		E:   secret.EncodeBase64(big.NewInt(int64(privateKey.E)).Bytes()),
	}

	return jwk, nil
}
