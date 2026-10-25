package request

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

// UserRegisterRequest Provides a generalized structure for processing user registration requests
type UserRegisterRequest struct {
	// Email - The primary email address for the user. Must be unique
	Email string `json:"email" bson:"email" validate:"required,email"`

	// Password - The plain text password for the user. Will be hashed on the server-side using Argonv2ID
	Password string `json:"password" bson:"password" validate:"required,password"`
}

// validateEmail Ensures that the user has provided a valid email address
func (request *UserRegisterRequest) validateEmail(fl validator.FieldLevel) bool {
	if !regexp.MustCompile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$").MatchString(fl.Field().String()) {
		return false
	}

	return true
}

// validatePassword Ensures that the user has not provided a password that was too short/long.
//
// TODO: This should be exposed as configuration
func (request *UserRegisterRequest) validatePassword(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if len(val) < 12 {
		return false
	}

	if len(val) > 64 {
		return false
	}

	return true
}

// Validate Ensures the user has provided a valid registration request
func (request *UserRegisterRequest) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.RegisterValidation("email", request.validateEmail); err != nil {
		return err
	}

	if err := validate.RegisterValidation("password", request.validatePassword); err != nil {
		return err
	}

	if err := validate.Struct(request); err != nil {
		return err
	}

	return nil
}
