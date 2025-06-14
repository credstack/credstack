package key

import (
	"crypto/rand"
	"crypto/rsa"
)

/*
GenerateKey - Generates a 4096-bit RSA Key Pair. The size on this is not adjustable as we want to maximize our entropy
with 4096-bit keys. After the key is generated, it is validated to ensure that it can be used for signing tokens. Any
errors here are propagated with the second return type
*/
func GenerateKey() (*rsa.PrivateKey, error) {
	/*
		First we want to generate our key here. Since we don't need to conform to user provided size, we can always
		use the 4096 as the size in bits.

		The first parameter of our GenerateKey function, wants an io.Reader to provide random bytes from. It is
		recommended to use rand.Reader here as this can generate cryptographically random bytes to use as the
		basis of our Key

		Notice that we are not calling key.Validate after this function. This is because when rsa.GenerateKey is called,
		it will automatically check the correctness of the Key
	*/
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	return key, nil
}
