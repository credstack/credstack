package secret

import (
	"crypto/subtle"

	"github.com/credstack/credstack/sdk/pkg/config"
	"golang.org/x/crypto/argon2"
)

/*
NewArgon2Hash - Generates a ArgonV2ID hash for the secret provided in the first parameter. Any options that are provided
here for hashing should be persisted using the user.UserCredential model as this ensures the same ones can be used
when you need to validate the hash

Unlike other functions implemented in this library, the config parameter is forced. This is done to ensure that the
caller is fully aware of the parameters that they are passing to this function.
*/
func NewArgon2Hash(secret []byte, config config.CredentialConfig) ([]byte, []byte, error) {
	/*
		First we generate some secured random bytes to serve as our salt for our password hash
	*/
	salt, err := RandBytes(config.SaltLength)
	if err != nil {
		return nil, nil, err
	}

	/*
		Then we generate our ArgonV2ID hash so that we can persist it for the user
	*/
	key := argon2.IDKey(
		secret,
		salt,
		config.Time,
		config.Memory,
		config.Threads,
		config.KeyLength,
	)

	return key, salt, nil
}

/*
ValidateArgon2Hash - Validates that the hashed result of 'secret' matches the hash provided in 'target'. The secret
parameter should be a raw, non-encoded secret provided by the user. The salt parameter should be the salt that both
hashes share, and the target parameter should be an Argon2 hashed secret. The salt is required here as it ensures that
we can adequately hash the result. Any options provided with config, should reflect what is stored in the
user.UserCredential structure.

A returned value of true indicates that the hashes match, any other result indicates that they do not
*/
func ValidateArgon2Hash(secret []byte, salt []byte, target []byte, config config.CredentialConfig) bool {
	/*
		This function call is generally expensive as we always need to re-hash the secret that is passed here.
	*/
	key := argon2.IDKey(
		secret,
		salt,
		config.Time,
		config.Memory,
		config.Threads,
		config.KeyLength,
	)

	/*
		subtle.ConstantTimeCompare provides a time-safe way of comparing password hashes. This protects
		us against time-based attacks during comparison
	*/
	result := subtle.ConstantTimeCompare(target, key)
	if result != 1 {
		return false
	}

	return true
}
