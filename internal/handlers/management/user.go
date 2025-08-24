package management

import (
	"strconv"

	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/pkg/server"
	"github.com/credstack/credstack/pkg/user"
	"github.com/gofiber/fiber/v3"
)

/*
GetUserHandler - Provides a Fiber handler for processing a get request to /management/user. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func GetUserHandler(c fiber.Ctx) error {
	email := c.Query("email")
	if email == "" {
		limit, err := strconv.Atoi(c.Query("limit", "10"))
		if err != nil {
			return middleware.HandleError(c, err)
		}

		users, err := user.List(server.HandlerCtx, limit, false)
		if err != nil {
			return middleware.HandleError(c, err)
		}

		return c.JSON(users)
	}

	requestedUser, err := user.Get(server.HandlerCtx, email, false)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.JSON(requestedUser)
}

/*
PatchUserHandler - Provides a Fiber handler for processing a PATCH request to /management/user. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func PatchUserHandler(c fiber.Ctx) error {
	email := c.Query("email")

	var model user.User

	err := middleware.BindJSON(c, &model)
	if err != nil {
		return err
	}

	err = user.Update(server.HandlerCtx, email, &model)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(200).JSON(&fiber.Map{"message": "Updated user successfully"})
}

/*
DeleteUserHandler - Provides a Fiber handler for processing a DELETE request to /management/user. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func DeleteUserHandler(c fiber.Ctx) error {
	email := c.Query("email")

	err := user.Delete(server.HandlerCtx, email)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(200).JSON(fiber.Map{"message": "Successfully deleted user"})
}
