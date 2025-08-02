package flow

import (
	"crypto/subtle"
	"github.com/credstack/credstack-lib/application"
	"github.com/credstack/credstack-lib/oauth/claim"
	"github.com/credstack/credstack-lib/oauth/token"
	"github.com/credstack/credstack-lib/server"
	"github.com/credstack/credstack-models/proto/request"
	tokenModel "github.com/credstack/credstack-models/proto/token"
)

/*
ClientCredentialsFlow - Attempts to issue a token under Client Credentials flow and begins any validation required for
ensuring that the request received was valid.
*/
func ClientCredentialsFlow(serv *server.Server, request *request.TokenRequest, issuer string) (*tokenModel.TokenResponse, error) {
	userApi, app, err := initiateAuthFlow(serv, request)
	if err != nil {
		return nil, err
	}

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
		userApi.Audience,
		app.ClientId,
		app.TokenLifetime,
	)

	tokenResp, err := token.NewToken(serv, userApi, app, tokenClaims)
	if err != nil {
		return nil, err
	}

	return tokenResp, nil
}
