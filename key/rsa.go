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
GenerateKey - Generates a 4096-bit RSA Key Pair. The size on this is not adjustable as we want to maximize our entropy
with 4096-bit keys. After the key is generated, it is validated to ensure that it can be used for signing tokens. Any
errors here are propagated with the second return type

Generally, this function is very slow as not only do we have to generate a 4096-bit private key, but we also need to get
the checksum of its public exponent. This **should** be ok, as this really only needs to get called on first startup, or
whenever the user requests key rotation. Generating a new key with this function will automatically mark it as active
*/
func GenerateKey() (*key.PrivateJSONWebKey, *key.JSONWebKey, error) {
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

/*
RSAtoJWK - Extracts the public key from an RSA Private Key and converts it to the JWK model

TODO: This may not be needed, validate as the rest of this package gets fleshed out
*/
func RSAtoJWK(keyPair *key.PrivateJSONWebKey) (*key.JSONWebKey, error) {
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
