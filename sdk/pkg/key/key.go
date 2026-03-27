package key

import (
	credstackError "github.com/credstack/credstack/sdk/pkg/errors"
	"github.com/credstack/credstack/sdk/pkg/oauth/token"
	"github.com/golang-jwt/jwt/v5"
)

// ErrAlgNotSupported Returned when the caller tries to sign a token wtih an algorithm that the key does not support
var ErrAlgNotSupported = credstackError.NewError(400, "SIGN_ALG_NOT_SUPPORTED", "token: The private key does not support signing tokens of this algorithm")

// PrivateKey Represents a private key used for signing verifying Access Tokens
type PrivateKey interface {
	// Sign Uses the private key to generate a signature of a JWT Token
	Sign(jwt.RegisteredClaims, jwt.SigningMethod, uint32) (*token.Token, error)

	// Verify Check's a JWT and returns true or false if the token is valid
	Verify(*jwt.Token) (bool, error)

	// Audience The audience that this key was generated for
	Audience() string

	// Current Set to true if the key can be used for signing, false if not
	Current() bool

	// Id Returns the ID of the private key used. Used as the 'kid' field in the claims of tokens signed with the key
	Id() string
}
