package middleware

import (
	"fmt"

	"github.com/gofiber/fiber/v3"
)

/*
BindJSON - Bind's a response to a protobuf message and wraps any errors that occur with ErrFailedToBindResponse
*/
func BindJSON(c fiber.Ctx, model interface{}) error {
	err := c.Bind().JSON(model)
	if err != nil {
		wrappedErr := fmt.Errorf("%w (%v)", ErrFailedToBindResponse, err)
		return HandleError(c, wrappedErr)
	}

	return nil
}
