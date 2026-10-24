package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/credstack/credstack/pkg/models/header"
	"github.com/credstack/credstack/pkg/secret"
)

const RSAKeySize int = 2048

// PrivateJSONWebKey Represents a private key used for signing JWTs
type PrivateJSONWebKey struct {
	// Header The header assigned to the JWK
	Header *header.Header `json:"header" bson:"header"`

	// Alg Specifies the algorithm used to generate the key. Most commonly RSA
	Alg string `json:"alg" bson:"alg"`

	// KeyMaterial The private key material used for signing tokens as a b64 encoded string
	KeyMaterial string `json:"key_material" bson:"key_material"`

	// Size The size of the key in bits
	Size int64 `json:"size" bson:"size"`

	// IsCurrent If set to true, then this is the current key used for signing. If false, then the key is "revoked"
	IsCurrent bool `json:"is_current" bson:"is_current"`

	// Audience The audience that this key is signing tokens for
	Audience string `json:"audience" bson:"audience"`
}

// RSA Converts a private JSON Web Key into a rsa.PrivateKey struct so that it can be used with the crypto/rsa
// package. After the key is parsed, it is checked for mathematical correctness using key.Validate
func (key *PrivateJSONWebKey) RSA() (*rsa.PrivateKey, error) {
	keyBytes := []byte(key.KeyMaterial)
	decoded, err := secret.DecodeBase64(keyBytes, uint32(len(keyBytes)))
	if err != nil {
		return nil, fmt.Errorf("jwk: Failed to decode private key bytes %v", err)
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("jwk: Failed to parse private key %v", err)
	}

	// TODO: Bad cast
	privateKey := parsedKey.(*rsa.PrivateKey)
	err = privateKey.Validate()
	if err != nil {
		return nil, fmt.Errorf("jwk: Parsed private key is not valid %v", err)
	}

	return privateKey, nil
}

// NewPrivateKey - Generates a 2048-bit RSA Key Pair. After the key is generated, it is validated to ensure that it can be used for signing tokens.
//
// Generally, this function is very slow as not only do we have to generate a 2048-bit private key, but we also need to get
// the checksum of its public exponent. This **should** be ok, as this really only needs to get called on first startup, or
// whenever the user requests key rotation. Generating a new key with this function will automatically mark it as active
//
// TODO: Only supports RSA for now, this should be updated to support other key types
func NewPrivateKey(audience string) (*PrivateJSONWebKey, *JSONWebKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("jwk: Failed to generate private key %v", err)
	}

	keyHeader := header.New(privateKey.PublicKey.N.String())
	jwk := &JSONWebKey{
		Use: "sig",
		Kty: "RSA",
		Alg: "RS256",
		Kid: keyHeader.Identifier,
		N:   secret.EncodeBase64(privateKey.PublicKey.N.Bytes()),
		E:   secret.EncodeBase64(big.NewInt(int64(privateKey.E)).Bytes()),
	}

	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("jwk: Failed to marshal private key %v", err)
	}

	ret := &PrivateJSONWebKey{
		Alg:         "RS256",
		Header:      keyHeader,
		KeyMaterial: secret.EncodeBase64(encoded),
		Size:        int64(RSAKeySize),
		IsCurrent:   true,
		Audience:    audience,
	}

	return ret, jwk, nil
}
