package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/stevezaluk/credstack-lib/header"
	"github.com/stevezaluk/credstack-lib/proto/key"
	"github.com/stevezaluk/credstack-lib/secret"
	"math/big"
)

const RSAKeySize int = 4096

/*
GenerateRSAKey - Generates a 4096-bit RSA Key Pair. The size on this is not adjustable as we want to maximize our entropy
with 4096-bit keys. After the key is generated, it is validated to ensure that it can be used for signing tokens. Any
errors here are propagated with the second return type

Generally, this function is very slow as not only do we have to generate a 4096-bit private key, but we also need to get
the checksum of its public exponent. This **should** be ok, as this really only needs to get called on first startup, or
whenever the user requests key rotation. Generating a new key with this function will automatically mark it as active
*/
func GenerateRSAKey() (*key.PrivateJSONWebKey, *key.JSONWebKey, error) {
	/*
		First we want to generate our key here. Since we don't need to conform to user provided size, we can always
		use the 4096 as the size in bits.

		The first parameter of our GenerateKey function, wants an io.Reader to provide random bytes from. It is
		recommended to use rand.Reader here as this can generate cryptographically random bytes to use as the
		basis of our Key

		Notice that we are not calling key.Validate after this function. This is because when rsa.GenerateKey is called,
		it will automatically check the correctness of the Key
	*/
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, nil, err
	}

	/*
		We also want to take the checksum of our public exponent so that we can use it as the basis for our header. This
		creates a nice, re-producible way of getting this value again.
	*/
	checksum := sha256.Sum256(privateKey.PublicKey.N.Bytes())

	/*
		We always use the same KID as we want to be able to identify both using a single identifier
	*/
	keyHeader := header.NewHeader(hex.EncodeToString(checksum[:]))

	/*
		To ensure that we don't need to re-convert our RSAPrivateKey back to a JWK immediately after
		generation, we can just have this function build us a JWK in addition to the private key.
	*/
	jwk := &key.JSONWebKey{
		Use: "sig",
		Kty: "RSA",
		Alg: "RS256",
		Kid: keyHeader.Identifier,
		N:   secret.EncodeBase64(privateKey.PublicKey.N.Bytes()),
		E:   secret.EncodeBase64(big.NewInt(int64(privateKey.E)).Bytes()),
	}

	/*
		Once we have our key, we want to marshal it to PKCS#8 to make it a bit easier to work with. Originally, I was
		going to store each of the keys components as base64 encoded strings however this was creating challenges when
		marshalling vs unmarshalling them

		We want to use PKCS#8 over PKCS#1 as the latter is legacy and only works for RSA private keys. By storing them
		as PKCS#8 we can at least create a standard across how we are marshaling our private keys
	*/
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	ret := &key.PrivateJSONWebKey{
		Header:      keyHeader,
		KeyMaterial: secret.EncodeBase64(encoded),
		Size:        int64(RSAKeySize),
		IsCurrent:   true,
	}

	return ret, jwk, nil
}

func ToRSAPrivateKey(private *key.PrivateJSONWebKey) (*rsa.PrivateKey, error) {
	/*
		Since our key is stored in base64 format in the database, we first must decode our resulting key. We always
		want to return an error here as well if we fail to decode
	*/
	keyBytes := []byte(private.KeyMaterial)
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
