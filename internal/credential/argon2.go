package credential

import (
	"crypto/subtle"

	"github.com/credstack/credstack/internal/secret"
	"golang.org/x/crypto/argon2"
)

// NewArgon2Hash - Generates a ArgonV2ID hash for the secret provided in the first parameter. Any options that are provided
// here for hashing should be persisted using the credential.Credential model as this ensures the same ones can be used
// when you need to validate the hash
func NewArgon2Hash(password []byte, config Config) ([]byte, []byte, error) {
	salt, err := secret.RandBytes(config.SaltLength)
	if err != nil {
		return nil, nil, err
	}

	key := argon2.IDKey(
		password,
		salt,
		config.Time,
		config.Memory,
		config.Threads,
		config.KeyLength,
	)

	return key, salt, nil
}

// ValidateArgon2Hash - Validates that the hashed result of 'secret' matches the hash provided in 'target'. The secret
// parameter should be a raw, non-encoded secret provided by the user. The salt parameter should be the salt that both
// hashes share, and the target parameter should be an Argon2 hashed secret.
func ValidateArgon2Hash(password []byte, salt []byte, target []byte, config Config) bool {
	key := argon2.IDKey(
		password,
		salt,
		config.Time,
		config.Memory,
		config.Threads,
		config.KeyLength,
	)

	// subtle.ConstantTimeCompare provides a time-safe way of comparing password hashes. Helps prevent
	// side-channel attacks
	result := subtle.ConstantTimeCompare(target, key)
	if result != 1 {
		return false
	}

	return true
}
