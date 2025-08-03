package middleware

import (
	"errors"
	credstackErrors "github.com/credstack/credstack/pkg/errors" // this needs to be fixed
	"github.com/gofiber/fiber/v3"
)

// ErrFailedToBindResponse - Provides a named error for when fiber can't bind a request body to a model
var ErrFailedToBindResponse = credstackErrors.NewError(400, "BIND_FAILED", "http: Failed to bind request/response body to model")

/*
HandleError - Takes a CredStack error and marshal's it into a JSON response
*/
func HandleError(c fiber.Ctx, err error) error {
	var casted credstackErrors.CredstackError

	if !errors.As(err, &casted) {
		return c.Status(500).JSON(fiber.Map{"message": err.Error()})
	}

	return c.Status(casted.HTTPStatusCode).JSON(fiber.Map{"error": casted.Short(), "message": casted.Error()})
}
