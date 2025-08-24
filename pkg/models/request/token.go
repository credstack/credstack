package request

/*
TokenRequest - Universal token request model for use in: Client credentials flow, authorization code flow, and
password grant flow
*/
type TokenRequest struct {
	// GrantType - Describes the type of OAuth grant flow you are using
	GrantType string `json:"grant_type" bson:"grant_type" query:"grant_type"`

	// ClientId - The client id of the application. Can be null in some cases
	ClientId string `json:"client_id" bson:"client_id" query:"client_id"`

	// ClientSecret - The client secret of the application. Can be null in some cases
	ClientSecret string `json:"client_secret" bson:"client_secret" query:"client_secret"`

	// Audience - The audience for the API you are requesting a token for
	Audience string `json:"audience" bson:"audience" query:"audience"`

	// Code - The code used in Authorization Code flow. Can be null in some cases
	Code string `json:"code" bson:"code" query:"code"`

	// RedirectUri -  The redirect URI used in Authorization code flow
	RedirectUri string `json:"redirect_uri" bson:"redirect_uri" query:"redirect_uri"`
}
