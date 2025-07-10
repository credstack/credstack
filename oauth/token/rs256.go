package token

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	"github.com/stevezaluk/credstack-lib/key"
	"github.com/stevezaluk/credstack-lib/oauth"
	"github.com/stevezaluk/credstack-lib/proto/response"

	keyModel "github.com/stevezaluk/credstack-lib/proto/key"
)

// ErrFailedToSignToken - An error that gets wrapped when jwt.Token.SignedString returns an error
var ErrFailedToSignToken = credstackError.NewError(500, "ERR_FAILED_TO_SIGN", "token: Failed to sign token due to an internal error")

/*
generateRS256 - Generates arbitrary RS256 tokens with the claims that are passed as an argument to this function. This
function doesn't provide logic for storing the token, and is completely unaware of OAuth authentication flows
*/
func generateRS256(rsKey *keyModel.PrivateJSONWebKey, claims jwt.RegisteredClaims) (*response.TokenResponse, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = rsKey.Header.Identifier

	/*
		To ensure that we can properly sign the token, we need to convert our keyModel.PrivateJSONWebKey to an RSA key
		that the token.SignedString function can actually use. This function is provided within the key package for
		this explicit purpose
	*/
	privateKey, err := key.ToRSAPrivateKey(rsKey)
	if err != nil {
		return nil, err
	}

	/*
		Once we have our singed string, we can simply pass it to the token.SignedString function. This function anticipates
		an interface, and when you pass jwt.SigningMethodRS256 to jwt.NewWithClaims, it expects a rsa.PrivateKey struct
	*/
	signedString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrFailedToSignToken, err)
	}

	resp, err := oauth.MarshalTokenResponse(token, signedString)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", oauth.ErrMarshalTokenResponse, err)
	}

	return resp, nil
}
