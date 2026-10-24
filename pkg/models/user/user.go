package user

import (
	"github.com/credstack/credstack/pkg/credential"
	"github.com/credstack/credstack/pkg/header"
	"github.com/go-playground/validator/v10"
)

type User struct {
	// Header The header for the User
	Header *header.Header `json:"header" bson:"header"`

	// Email The email for the user. Must be unique
	Email string `json:"email" bson:"email" validate:"required"`

	// Credential The structure containing the users hashed password
	Credential *credential.Credential `json:"credential,omitempty" bson:"credential"`

	// Scopes A string slice containing scopes that have been directly assigned to the user
	Scopes []string `json:"scopes" bson:"scopes" validate:"required"`

	// Roles A string slice containing roles that have been assigned to the user
	Roles []string `json:"roles" bson:"roles" validate:"required"`
}

func (user *User) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(user); err != nil {
		return err
	}

	return nil
}
