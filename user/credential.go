package user

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/stevezaluk/credstack-lib/options"
	"github.com/stevezaluk/credstack-models/proto/user"
	"golang.org/x/crypto/argon2"
	"io"
)

/*
hashSecret - Generates a ArgonV2ID hash for the secret provided in the first parameter. Any options that are provided
here for hashing should be persisted using the user.UserCredential model as this ensures the same ones can be used
when you need to validate the hash

Unlike other functions implemented in this library, the opts parameter is forced. This is done to ensure that the
caller is fully aware of the parameters that they are passing to this function.
*/
func hashSecret(secret []byte, opts *options.CredentialOptions) (string, string, error) {
	/*
		First we generate some random bytes to serve as our salt for our password hash
	*/
	salt := make([]byte, opts.SaltLength)

	/*
		Then we inject randomness into the bytes to increase entropy
	*/
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return "", "", err
	}

	/*
		Then we generate our ArgonV2ID hash so that we can persist it for the user
	*/
	key := argon2.IDKey(
		secret,
		salt,
		opts.Time,
		opts.Memory,
		opts.Threads,
		opts.KeyLength,
	)

	/*
		Finally we want to store our hash and salt as a base64 encoded string, as when we inject randomness,
		non-printable characters can be included. This provides a safer way of persisting our salts
	*/
	encodedHash := base64.URLEncoding.EncodeToString(key)
	encodedSalt := base64.URLEncoding.EncodeToString(salt)

	return encodedHash, encodedSalt, nil
}

/*
NewCredential - Creates and generates a new UserCredential using the secret provided in the parameter. Any errors
that occur are propagated using the second return value
*/
func NewCredential(secret string, opts *options.CredentialOptions) (*user.UserCredential, error) {
	hash, salt, err := hashSecret([]byte(secret), opts)
	if err != nil {
		return nil, err
	}

	return &user.UserCredential{
		Key:        hash,
		Salt:       salt,
		Time:       opts.Time,
		Memory:     opts.Memory,
		Threads:    uint32(opts.Threads),
		KeyLength:  opts.KeyLength,
		SaltLength: opts.SaltLength,
	}, nil
}
