package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"github.com/stevezaluk/credstack-lib/header"
	"github.com/stevezaluk/credstack-lib/proto/key"
	"github.com/stevezaluk/credstack-lib/secret"
)

const RSAKeySize int = 4096

/*
GenerateKey - Generates a 4096-bit RSA Key Pair. The size on this is not adjustable as we want to maximize our entropy
with 4096-bit keys. After the key is generated, it is validated to ensure that it can be used for signing tokens. Any
errors here are propagated with the second return type

Generally, this function is very slow as not only do we have to generate a 4096-bit private key, but we also need to get
the checksum of its public exponent. This **should** be ok, as this really only needs to get called on first startup, or
whenever the user requests key rotation
*/
func GenerateKey() (*key.RSAPrivateKey, error) {
	/*
		First we want to generate our key here. Since we don't need to conform to user provided size, we can always
		use the 4096 as the size in bits.

		The first parameter of our GenerateKey function, wants an io.Reader to provide random bytes from. It is
		recommended to use rand.Reader here as this can generate cryptographically random bytes to use as the
		basis of our Key

		Notice that we are not calling key.Validate after this function. This is because when rsa.GenerateKey is called,
		it will automatically check the correctness of the Key
	*/
	generatedKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, err
	}

	/*
		We also want to take the checksum of our public exponent so that we can use it as the basis for our header. This
		creates a nice, re-producible way of getting this value again.
	*/
	checksum := sha256.Sum256(generatedKey.PublicKey.N.Bytes())

	/*
		Once we have our key, we want to marshal it to PKCS#8 to make it a bit easier to work with. Originally, I was
		going to store each of the keys components as base64 encoded strings however this was creating challenges when
		marshalling vs unmarshalling them

		We want to use PKCS#8 over PKCS#1 as the latter is legacy and only works for RSA private keys. By storing them
		as PKCS#8 we can at least create a standard across how we are marshaling our private keys
	*/
	encoded, err := x509.MarshalPKCS8PrivateKey(generatedKey)
	if err != nil {
		return nil, err
	}

	ret := &key.RSAPrivateKey{
		Header:      header.NewHeader(hex.EncodeToString(checksum[:])),
		KeyMaterial: secret.EncodeBase64(encoded),
		Size:        int64(RSAKeySize),
	}

	return ret, nil
}
