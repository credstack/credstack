package flow

import (
	"crypto/subtle"
	"github.com/credstack/credstack-lib/application"
	"github.com/credstack/credstack-lib/oauth/claim"
	apiModel "github.com/credstack/credstack-lib/proto/api"
	applicationModel "github.com/credstack/credstack-lib/proto/application"
	tokenModel "github.com/credstack/credstack-lib/proto/request"
	"github.com/golang-jwt/jwt/v5"
)

/*
ClientCredentialsFlow - Attempts to issue a token under Client Credentials flow and begins any validation required for
ensuring that the request received was valid.
*/
func ClientCredentialsFlow(app *applicationModel.Application, api *apiModel.API, request *tokenModel.TokenRequest, issuer string) (*jwt.RegisteredClaims, error) {
	/*
		Only confidential applications are able to issue tokens under client credentials flow. Similar to our credentials
		validation, we do this before anything else as we can't proceed with the token generation if this is true
	*/
	if app.IsPublic {
		return nil, application.ErrVisibilityIssue
	}

	/*
		We use subtle.ConstantTimeCompare here to ensure that we are protected from side channel attacks on the
		server itself. Ideally, any credential validation that requires a direct comparison would use ConstantTimeCompare.

		Any value returned by this function other than 1, indicates a failure
	*/
	if subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(request.ClientSecret)) != 1 {
		return nil, application.ErrInvalidClientCredentials
	}

	tokenClaims := claim.NewClaimsWithSubject(
		issuer,
		api.Audience,
		app.ClientId,
		app.TokenLifetime,
	)

	return &tokenClaims, nil
}
