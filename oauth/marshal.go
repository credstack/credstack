package oauth

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	"github.com/stevezaluk/credstack-lib/proto/response"
)

// ErrMarshalTokenResponse - An error that gets returned
var ErrMarshalTokenResponse = credstackError.NewError(400, "ERR_MARSHAL_TOKEN_RESPONSE", "token: Failed to marshal token into token response")

/*
MarshalTokenResponse - Converts jwt.Token structures into response.TokenResponse structures so that they can be returned
effectively

TODO: Need support for id tokens and refresh tokens here
TODO: Expires in is not rendering properly, showing expiration instead of token lifetime
TODO: This function feels kind of clunky...
*/
func MarshalTokenResponse(tok *jwt.Token, signedString string) (*response.TokenResponse, error) {
	expirationDate, err := tok.Claims.GetExpirationTime()
	if err != nil {
		// wrapping this error with ErrFailedToSignToken is not ideal as it can lead to some confusion on
		// how this function failed but... oh well!
		return nil, fmt.Errorf("%w (%v)", ErrMarshalTokenResponse, err)
	}

	/*
		After we actually sign our token, we can quickly convert it back into a response.TokenResponse structure so that
		it can be returned from the API
	*/
	signedResponse := &response.TokenResponse{
		AccessToken:  signedString,
		TokenType:    "Bearer",
		ExpiresIn:    uint32(expirationDate.Time.Unix()), // this is bad, could lose precision by down converting to uint32
		RefreshToken: "",
		IdToken:      "",
		Scope:        "",
	}

	return signedResponse, nil
}
