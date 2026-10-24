package request

import "github.com/go-playground/validator/v10"

/*
TokenRequest - Universal token request model for use in: Client credentials flow, authorization code flow, and
password grant flow
*/
type TokenRequest struct {
	// GrantType - Describes the type of OAuth grant flow you are using
	GrantType string `json:"grant_type" bson:"grant_type" form:"grant_type" validate:"required,oneof=authorization_code client_credentials"`

	// ClientId - The client id of the application. Can be null in some cases
	ClientId string `json:"client_id" bson:"client_id" form:"client_id" validate:"required"`

	// ClientSecret - The client secret of the application. Can be null in some cases
	ClientSecret string `json:"client_secret" bson:"client_secret" form:"client_secret"`

	// Audience - The audience for the API you are requesting a token for
	Audience string `json:"audience" bson:"audience" form:"audience" validate:"required"`

	// Code - The code used in Authorization Code flow. Can be null in some cases
	Code string `json:"code" bson:"code" form:"code"`

	// RedirectUri -  The redirect URI used in Authorization code flow
	RedirectUri string `json:"redirect_uri" bson:"redirect_uri" form:"redirect_uri"`
}

func (request *TokenRequest) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(request); err != nil {
		return err
	}

	return nil
}
