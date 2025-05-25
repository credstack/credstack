package user

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"github.com/stevezaluk/credstack-lib/internal"
	"github.com/stevezaluk/credstack-lib/options"
	"github.com/stevezaluk/credstack-models/proto/user"
	"golang.org/x/crypto/argon2"
	"io"
)

// ErrUserCredentialInvalid - Provides a named error for when user credential validation fails
var ErrUserCredentialInvalid = internal.NewError(401, "INVALID_USER_CREDENTIAL", "user: invalid credentials")

// ErrFailedToHashCredential - Provides a named error for when user credential hashing has failed
var ErrFailedToHashCredential = internal.NewError(500, "FAILED_TO_HASH_CREDENTIAL", "user: failed to hash user credential")

// ErrFailedToBaseDecode - Provides a named error for when base64 decoding data fails during a user credential validation
var ErrFailedToBaseDecode = internal.NewError(500, "FAILED_TO_BASE_DECODE", "user: failed to decode base64 data during user credential validation")

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
		return nil, fmt.Errorf("%w (%v)", ErrFailedToHashCredential, err)
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

/*
ValidateSecret - Validates that a user provided secret is identical to the secret provided in the credential parameter
*/
func ValidateSecret(secret []byte, credential *user.UserCredential) error {
	/*
		To start the validation process we first need to base64 decode the salt that was
		stored in MongoDB. We use make to allocate us a byte array of the requested salt length
	*/
	decodedSalt := make([]byte, credential.SaltLength)
	n, err := base64.URLEncoding.Decode(decodedSalt, []byte(credential.Salt))
	if err != nil {
		return fmt.Errorf("%w (%v)", ErrFailedToBaseDecode, err)
	}

	/*
		We always want to decode our values first to ensure that we can catch any basic errors
		before we start Argon hash generation
	*/
	decodedHash := make([]byte, credential.KeyLength)
	m, err := base64.URLEncoding.Decode(decodedHash, []byte(credential.Key))
	if err != nil {
		return fmt.Errorf("%w (%v)", ErrFailedToBaseDecode, err)
	}

	/*
		The once we have our decoded salt, we can use Argon to generate us a fresh hash
		using the parameters stored with the user credential
	*/
	key := argon2.IDKey(
		secret,
		decodedSalt[:n],
		credential.Time,
		credential.Memory,
		uint8(credential.Threads),
		credential.KeyLength,
	)

	/*
		subtle.ConstantTimeCompare provides a time-safe way of comparing password hashes. This protects
		us against time-based attacks during comparison
	*/
	result := subtle.ConstantTimeCompare(key, decodedHash[:m])
	if result != 1 {
		return ErrUserCredentialInvalid
	}

	return nil
}
