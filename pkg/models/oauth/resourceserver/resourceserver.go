package resourceserver

import (
	"github.com/credstack/credstack/pkg/models/header"
	"github.com/go-playground/validator/v10"
)

// ResourceServer Represents the OAuth resource server and contains metadata for validating tokens
type ResourceServer struct {
	// header The header for the resource server
	Header *header.Header `json:"header" bson:"header"`

	// Name The name of the resource server chosen by the caller
	Name string `json:"name" bson:"name" validate:"required"`

	// Audience An identifier for the resource server, usually formatted as a domain
	Audience string `json:"audience" bson:"audience" validate:"required"`

	// TokenType The type of tokens that the API should validate
	TokenType string `json:"token_type" bson:"token_type" validate:"required,oneof=RS256"`

	// EnforceRBAC If set to true, then the API will evaluate scopes and roles during validation (and will insert them as claims in the token)
	EnforceRBAC bool `json:"enforce_rbac" bson:"enforce_rbac"`
}

func (resourceServer *ResourceServer) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(resourceServer); err != nil {
		return err
	}

	return nil
}
