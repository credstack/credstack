package token

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/stevezaluk/credstack-lib/key"
	keyModel "github.com/stevezaluk/credstack-lib/proto/key"
)

/*
GenerateRS256 - Generates arbitrary RS256 tokens with the claims that are passed as an argument to this function. This
function doesn't provide logic for storing the token, and is completely unaware of OAuth authentication flows
*/
func GenerateRS256(rsKey *keyModel.PrivateJSONWebKey, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	/*
		To ensure that we can properly sign the token, we need to convert our keyModel.PrivateJSONWebKey to an RSA key
		that the token.SignedString function can actually use. This function is provided within the key package for
		this explicit purpose
	*/
	privateKey, err := key.ToRSAPrivateKey(rsKey)
	if err != nil {
		return "", err
	}

	/*
		Once we have our singed string, we can simply pass it to the token.SignedString function. This function anticipates
		an interface, and when you pass jwt.SigningMethodRS256 to jwt.NewWithClaims, it expects a rsa.PrivateKey struct
	*/
	signedString, err := token.SignedString(privateKey)
	if err != nil {
		// this error needs to be wrapped
		return "", err
	}

	return signedString, nil
}
