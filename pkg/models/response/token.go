package response

/*
TokenResponse - Represents an HTTP response containing the credentials requested by the end user
*/
type TokenResponse struct {
	// AccessToken - The access token that was issued
	AccessToken string `json:"access_token" bson:"access_token"`

	// IdToken - The id token that was issued
	IdToken string `json:"id_token" bson:"id_token"` // omit if empty

	// TokenType - The type of access token that has been returned
	TokenType string `json:"token_type" bson:"token_type"`

	// ExpiresIn - The amount of time (in seconds) that the access token expires in
	ExpiresIn uint32 `json:"expires_in" bson:"expires_in"`

	// RefreshToken - The refresh tokne that was issued
	RefreshToken string `json:"refresh_token" bson:"refresh_token"` // omit if empty

	// Scope - A list of permission scopes that are associated with the claims of the token
	Scope string `json:"scope" bson:"scope"` // omit if empty
}
