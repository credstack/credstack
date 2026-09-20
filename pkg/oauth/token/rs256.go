package token

import (
	"fmt"
	"time"

	"github.com/credstack/credstack/pkg/oauth/jwk"
	"github.com/golang-jwt/jwt/v5"
)

/*
RS256 - Generates arbitrary RS256 tokens with the claims that are passed as an argument to this function. This
function doesn't provide logic for storing the token, and is completely unaware of OAuth authentication flows

TODO: ExpiresIn is a bit arbitrary here, this can be pulled this from the claims
*/
func RS256(rsKey *jwk.PrivateJSONWebKey, claims jwt.RegisteredClaims, expiresIn uint32) (*Token, error) {
	generatedJwt := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	generatedJwt.Header["kid"] = rsKey.Header.Identifier

	/*
		To ensure that we can properly sign the token, we need to convert our jwkModel.PrivateJSONWebKey to an RSA key
		that the token.SignedString function can actually use. This function is provided within the key package for
		this explicit purpose
	*/
	privateKey, err := rsKey.RSA()
	if err != nil {
		return nil, err
	}

	/*
		Once we have our singed string, we can simply pass it to the token.SignedString function. This function anticipates
		an interface, and when you pass jwt.SigningMethodRS256 to jwt.NewWithClaims, it expects a rsa.PrivateKey struct
	*/
	sig, err := generatedJwt.SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrFailedToSignToken, err)
	}

	/*
		Marshal the generated JWT into a structure that we can actually store in the database
	*/
	token := &Token{
		Subject:     claims.Subject,
		AccessToken: sig,
		ExpiresIn:   expiresIn,
		ExpiresAt:   time.Now().UTC().Add(time.Duration(expiresIn) * time.Second),
	}

	return token, nil
}
