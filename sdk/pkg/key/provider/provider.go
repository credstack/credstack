package provider

import (
	credstackError "github.com/credstack/credstack/sdk/pkg/errors"
	"github.com/credstack/credstack/sdk/pkg/key"
)

var ErrKeyNotExist = credstackError.NewError(404, "ERR_PRIV_KEY_NOT_EXIST", "jwk: Failed to find private key with the requested key ID")

// Provider Represents a Key Provider that can be used to fetch keys for signing
type Provider interface {
	// generate Generates a new private key and inserts it into the database
	generate(string, string, bool) error

	// Count Returns the current number of keys that are available for signing
	Count(string, string, bool) (int, error)

	// ActiveKey Returns the currently active signing key for JWT's
	ActiveKey(string, string) (key.PrivateKey, error)

	// Rotate Rotates all private key's. Does not invalidate them for validation
	Rotate(string, string) error

	// RotateRevoke Rotates all private keys, and revokes previously used keys
	RotateRevoke(string, string) error
}
