package token

import (
	"fmt"
	"time"

	"github.com/credstack/credstack/pkg/secret"
	"github.com/golang-jwt/jwt/v5"
)

/*
HS256 - Generates arbitrary HS256 tokens with the claims that are passed as an argument to the function. It is
expected that a base64 encoded secret string (like the ones generated from secret.RandString) is used as the secret here.
When used with ClientCredentials flow, the client secret is expected here. As a result, the KID field is not added to the
header with this function either as both the issuing and validating party must both know the client secret

TODO: ExpiresIn is a bit arbitrary here, this can be pulled this from the claims
*/
func HS256(clientSecret string, claims jwt.RegisteredClaims, expiresIn uint32) (*Token, error) {
	generatedJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	/*
		Unlike RS256 tokens, the client secret is simply used to sign the token with SigningMethodHS256. This provides
		s shared secret that both the issuer and the validator a shared secret that both parties can agree on. Client
		secrets are issued pretty simply, as its really just a base64 encoded version of the byte result of rand.Read
	*/
	decodedBytes := []byte(clientSecret)
	decoded, err := secret.DecodeBase64(decodedBytes, uint32(len(decodedBytes)))
	if err != nil {
		return nil, err
	}

	/*
		Then we just sign the token with the decoded secret.
	*/
	sig, err := generatedJwt.SignedString(decoded)
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
