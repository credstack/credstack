package flow

import (
	"crypto/subtle"
	"github.com/credstack/credstack-lib/application"
	"github.com/credstack/credstack-lib/oauth/claim"
	"github.com/credstack/credstack-lib/oauth/token"
	"github.com/credstack/credstack-lib/server"
	tokenModel "github.com/credstack/credstack-models/proto/token"
)

/*
ClientCredentialsFlow - Attempts to issue a token under Client Credentials flow and begins any validation required for
ensuring that the request received was valid.
*/
func ClientCredentialsFlow(serv *server.Server, ticket *tokenModel.AuthenticationTicket, issuer string) (*tokenModel.TokenResponse, error) {

	/*
		Only confidential applications are able to issue tokens under client credentials flow. Similar to our credentials
		validation, we do this before anything else as we can't proceed with the token generation if this is true
	*/
	if ticket.Application.IsPublic {
		return nil, application.ErrVisibilityIssue
	}

	/*
		We use subtle.ConstantTimeCompare here to ensure that we are protected from side channel attacks on the
		server itself. Ideally, any credential validation that requires a direct comparison would use ConstantTimeCompare.

		Any value returned by this function other than 1, indicates a failure
	*/
	if subtle.ConstantTimeCompare([]byte(ticket.Application.ClientSecret), []byte(ticket.TokenRequest.ClientSecret)) != 1 {
		return nil, application.ErrInvalidClientCredentials
	}

	tokenClaims := claim.NewClaimsWithSubject(
		issuer,
		ticket.Api.Audience,
		ticket.Application.ClientId,
		ticket.Application.TokenLifetime,
	)

	tokenResp, err := token.NewToken(serv, ticket, tokenClaims)
	if err != nil {
		return nil, err
	}

	return tokenResp, nil
}
