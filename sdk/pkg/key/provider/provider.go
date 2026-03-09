package provider

import "github.com/credstack/credstack/sdk/pkg/key"

// Provider Represents a Key Provider that can be used to fetch keys for signing
type Provider interface {
	// ActiveKey Returns the currently active signing key for JWT's
	ActiveKey(string, string) (key.PrivateKey, error)

	// Rotate Rotates all private key's. Does not invalidate them for validation
	Rotate(string, string) error

	// RotateRevoke Rotates all private keys, and revokes previously used keys
	RotateRevoke(string, string) error
}
