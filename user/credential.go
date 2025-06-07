package user

import (
	"fmt"
	"github.com/stevezaluk/credstack-lib/internal"
	"github.com/stevezaluk/credstack-lib/options"
	"github.com/stevezaluk/credstack-lib/proto/user"
	"github.com/stevezaluk/credstack-lib/secret"
)

// ErrUserCredentialInvalid - Provides a named error for when user credential validation fails
var ErrUserCredentialInvalid = internal.NewError(401, "INVALID_USER_CREDENTIAL", "user: invalid credentials")

// ErrFailedToHashCredential - Provides a named error for when user credential hashing has failed
var ErrFailedToHashCredential = internal.NewError(500, "FAILED_TO_HASH_CREDENTIAL", "user: failed to hash user credential")

/*
NewCredential - Creates and generates a new UserCredential using the secret provided in the parameter. Both the secret
and the salt are stored as URL-Safe, base64 encoded strings to ensure that they can be safely stored in Mongo. Any
errors that occur here are returned in the wrapped error: ErrFailedToHashCredential.
*/
func NewCredential(credential string, opts *options.CredentialOptions) (*user.UserCredential, error) {
	/*
		All logic for generating Argon2 Hashes are provided by the secrets package. A new cryptographically secure salt
		is generated from this function call, however returned values are not base64 encoded or marshalled into the
		UserCredential structure.
	*/
	hash, salt, err := secret.NewArgon2Hash([]byte(credential), opts)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrFailedToHashCredential, err)
	}

	/*
		After our credentials are generated, we marshal them into the user.UserCredentials struct and return it to
		the caller. Any secrets generated are base64 encoded here (URL Safe)
	*/
	return &user.UserCredential{
		Key:        internal.EncodeBase64(hash),
		Salt:       internal.EncodeBase64(salt),
		Time:       opts.Time,
		Memory:     opts.Memory,
		Threads:    uint32(opts.Threads),
		KeyLength:  opts.KeyLength,
		SaltLength: opts.SaltLength,
	}, nil
}

/*
CheckCredential - Validates the base64 encoded secret passed in the 'validate' parameter against the UserCredential
struct passed in the credential parameter. This should be a UserCredential struct returned from a call to GetUser. If
the user credentials do not match, then ErrUserCredentialInvalid is returned. Otherwise, nil is returned
*/
func CheckCredential(validate string, credential *user.UserCredential) error {
	/*
		To start the validation process we first need to base64 decode the salt that was
		stored in MongoDB. We use make to allocate us a byte array of the requested salt length
	*/
	decodedSalt, err := internal.DecodeBase64([]byte(credential.Salt), credential.SaltLength)
	if err != nil {
		return err // these are named already so we don't need to wrap again
	}

	/*
		We always want to decode our values first to ensure that we can catch any basic errors
		before we start Argon hash generation
	*/
	decodedHash, err := internal.DecodeBase64([]byte(credential.Key), credential.KeyLength)
	if err != nil {
		return err // these are named already so we don't need to wrap again
	}

	/*
		Finally, we pass our decoded values and our raw credential and pass them to ValidateArgon2Hash to check its
		validity. We need to create a separate CredentialOptions structure here as the secrets package has no awareness
		of the UserCredential structure.
	*/
	isValid := secret.ValidateArgon2Hash([]byte(validate), decodedSalt, decodedHash, &options.CredentialOptions{
		Time:      credential.Time,
		Memory:    credential.Memory,
		Threads:   uint8(credential.Threads),
		KeyLength: credential.KeyLength,
	})

	/*
		We return an error here instead of a boolean, so that when we implement this into the API, we don't need to do
		any extra work to convert an error response. All errors passed by functions should be able to just be directly
		marshalled to HTTP responses
	*/
	if !isValid {
		return ErrUserCredentialInvalid
	}

	return nil
}
