package key

import (
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/credstack/credstack/sdk/pkg/header"
	"github.com/credstack/credstack/sdk/pkg/oauth/token"
	"github.com/credstack/credstack/sdk/pkg/secret"
	"github.com/golang-jwt/jwt/v5"
)

type DatabasePrivateKey struct {
	// Header The header of the private key
	Header *header.Header `json:"header" bson:"header"`

	// Algorithm The encryption algorithm that was used to generate the private key
	Alg string `json:"algorithm" bson:"algorithm"`

	// Audience The audience that this key can be used to sign JWTs for
	Aud string `json:"audience" bson:"audience"`

	// IsCurrent Set to true if the key can be used for signing, false if not
	IsCurrent bool `json:"is_current" bson:"is_current"`

	// Material Base64 encoded private key material
	Material string `json:"key_material" bson:"key_material"`

	privateKey *rsa.PrivateKey
}

// load Creates a key.PrivateKey from pkcs11 private key material
func (key *DatabasePrivateKey) load() error {
	keyBytes := []byte(key.Material)
	decoded, err := secret.DecodeBase64(keyBytes, uint32(len(keyBytes)))
	if err != nil {
		return err
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(decoded)
	if err != nil {
		return err
	}

	privateKey := parsedKey.(*rsa.PrivateKey)
	err = privateKey.Validate()
	if err != nil {
		return err
	}

	key.privateKey = privateKey

	return nil
}

// Audience The audience that this key was generated for
func (key *DatabasePrivateKey) Audience() string {
	return key.Aud
}

// Current Set to true if the key can be used for signing, false if not
func (key *DatabasePrivateKey) Current() bool {
	return key.IsCurrent
}

// Id Returns the ID of the private key used. Used as the 'kid' field in the claims of tokens signed with the key
func (key *DatabasePrivateKey) Id() string {
	return key.Header.Identifier
}

// Sign Uses the private key to generate a signature of a JWT Token
func (key *DatabasePrivateKey) Sign(claims jwt.RegisteredClaims, alg jwt.SigningMethod, expiry uint32) (*token.Token, error) {
	if key.Alg != alg.Alg() {
		return nil, ErrAlgNotSupported // return err here
	}

	/*
		structs that implement key.PrivateKey do not have constructors as they are unmarshalled
		directly from database call results. Due to this architectural decision, rsa.PrivateKey must be
		generated on the first call to Sign. This can increase latency on the first token signing request
		each startup but given that keys are cached by the key provider, this **should** be fine
	*/
	if key.privateKey == nil {
		// this won't really properly support HS256. Creation of tech debt in real time
		err := key.load()
		if err != nil {
			return nil, err
		}
	}

	generatedToken := jwt.NewWithClaims(alg, claims)
	generatedToken.Header["kid"] = key.Id()

	sig, err := generatedToken.SignedString(key.privateKey)
	if err != nil {
		return nil, err
	}

	return &token.Token{
		Subject:     claims.Subject,
		AccessToken: sig,
		ExpiresIn:   expiry,
		ExpiresAt:   time.Now().UTC().Add(time.Duration(expiry) * time.Second),
	}, err
}

// Verify Check's a JWT and returns true or false if the token is valid
func (key *DatabasePrivateKey) Verify(token *jwt.Token) (bool, error) {
	return false, nil
}

// NewDatabasePrivateKey Constructs a DatabasePrivateKey from an existing rsa.PrivateKey
func NewDatabasePrivateKey(privateKey *rsa.PrivateKey) *DatabasePrivateKey {
	return &DatabasePrivateKey{
		privateKey: privateKey,
		IsCurrent:  false,
		Material:   "", // this needs to be populated
	}
}
