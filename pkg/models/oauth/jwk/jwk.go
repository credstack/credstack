package jwk

import (
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/credstack/credstack/internal/secret"
)

// JSONWebKey Represents a JSON Web Key used for signing tokens
type JSONWebKey struct {
	// Kty Defines the type of key this JWK represents
	Kty string `json:"kty" bson:"kty"`

	// Use Defines the use of this JWK, usually sig
	Use string `json:"use" bson:"use"`

	// Kid The unique identifier of the key
	Kid string `json:"kid" bson:"kid"`

	// Alg Defines the algorithm that this JWK was generated using
	Alg string `json:"alg" bson:"alg"`

	// N Public modulos for the key
	N string `json:"n" bson:"n"`

	// E Public exponent for the key
	E string `json:"e" bson:"e"`
}

// RSA Converts a public JSON Web Key into a rsa.PublicKey struct so that it can be used with the crypto/rsa package
func (key *JSONWebKey) RSA() (*rsa.PublicKey, error) {
	modulusBytes := []byte(key.N)
	decodedModulus, err := secret.DecodeBase64(modulusBytes, uint32(len(modulusBytes)))
	if err != nil {
		return nil, fmt.Errorf("jwk: Failed to decode modulus %v", err)
	}

	exponentBytes := []byte(key.E)
	decodedExponent, err := secret.DecodeBase64(exponentBytes, uint32(len(exponentBytes)))
	if err != nil {
		return nil, fmt.Errorf("jwk: Failed to decode exponent %v", err)
	}

	// Since the decoded exponent here is a big-endian byte array, we need to perform some bit shifting magic to be
	// able to convert this properly. Using strconv on a string representation of this won't work directly, and you
	// would get a parse error. Instead, we can shift each byte of the array by 8 bits (1-byte) and then add them
	// together to get our public exponent back
	modulus := new(big.Int).SetBytes(decodedModulus)
	exponent := 0
	for _, b := range decodedExponent {
		exponent = (exponent << 8) + int(b)
	}

	publicKey := rsa.PublicKey{
		N: modulus,
		E: exponent,
	}

	return &publicKey, nil
}
