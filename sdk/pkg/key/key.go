package key

import "github.com/golang-jwt/jwt/v5"

// PrivateKey Represents a private key used for signing verifying Access Tokens
type PrivateKey interface {
	// Sign Uses the private key to generate a signature of a JWT Token
	Sign(*jwt.Token) (string, error)

	// Verify Check's a JWT and returns true or false if the token is valid
	Verify(*jwt.Token) (bool, error)

	// Audience The audience that this key was generated for
	Audience() string

	// Current Set to true if the key can be used for signing, false if not
	Current() bool
}
