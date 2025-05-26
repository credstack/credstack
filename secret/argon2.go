package secret

import (
	"github.com/stevezaluk/credstack-lib/options"
	"golang.org/x/crypto/argon2"
)

/*
NewArgon2Hash - Generates a ArgonV2ID hash for the secret provided in the first parameter. Any options that are provided
here for hashing should be persisted using the user.UserCredential model as this ensures the same ones can be used
when you need to validate the hash

Unlike other functions implemented in this library, the opts parameter is forced. This is done to ensure that the
caller is fully aware of the parameters that they are passing to this function.
*/
func NewArgon2Hash(secret []byte, opts *options.CredentialOptions) ([]byte, []byte, error) {
	/*
		First we generate some secured random bytes to serve as our salt for our password hash
	*/
	salt, err := RandBytes(opts.SaltLength)
	if err != nil {
		return nil, nil, err
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

	return key, salt, nil
}
