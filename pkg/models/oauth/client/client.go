package client

import (
	"github.com/credstack/credstack/pkg/header"
	"github.com/go-playground/validator/v10"
)

// Client Represents the OAuth client that wants to issue tokens for an API
type Client struct {
	// Header The header for the Client. Created at object birth
	Header *header.Header `json:"header" bson:"header"`

	// Name The name of the Client as defined by the user
	Name string `bson:"name" json:"name" validate:"required"`

	// IsPublic Determines if the Client is public. If this is set to true, then the Client cannot ue Client Credentials Flow
	IsPublic bool `bson:"is_public" json:"is_public"`

	// ClientId The client ID for the Client. Gets generated at birth
	ClientId string `bson:"client_id" json:"client_id" validate:"required"`

	// ClientSecret The client secret for the Client. Gets generated at birth
	ClientSecret string `bson:"client_secret" json:"client_secret" validate:"required"`

	// RedirectURI The redirect URI for post-authentication. Defined by the user
	RedirectURI string `bson:"redirect_uri" json:"redirect_uri"`

	// TokenLifetime An unsigned integer representing the amount of time in seconds that the token is valid for
	TokenLifetime uint64 `bson:"token_lifetime" json:"token_lifetime" validate:"gte=3600"`

	// GrantTypes The grant types that the Client is allowed to issue tokens under
	GrantTypes []string `bson:"grant_types" json:"grant_types" validate:"required,gt=0,dive,oneof=authorization_code client_credentials"`

	// AllowedAudiences A string slice representing which ResourceServers are allowed to issue tokens for this Client
	AllowedAudiences []string `bson:"allowed_audiences" json:"allowed_audiences"`
}

// Validate Ensures that the structure is free of validation errors
func (client *Client) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(client); err != nil {
		return err
	}

	return nil
}
