package management

import (
	"github.com/credstack/credstack/internal/middleware"
	userModel "github.com/credstack/credstack/pkg/models/user"
	"github.com/credstack/credstack/pkg/server"
	"github.com/credstack/credstack/pkg/user"
	"github.com/gofiber/fiber/v3"
	"strconv"
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

		users, err := user.ListUser(server.HandlerCtx, limit, false)
		if err != nil {
			return middleware.HandleError(c, err)
		}

		return middleware.MarshalProtobufList(c, users)
	}

	requestedUser, err := user.GetUser(server.HandlerCtx, email, false)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return middleware.MarshalProtobuf(c, requestedUser)
}

/*
PatchUserHandler - Provides a Fiber handler for processing a PATCH request to /management/user. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func PatchUserHandler(c fiber.Ctx) error {
	email := c.Query("email")

	var model userModel.User

	err := middleware.BindJSON(c, &model)
	if err != nil {
		return err
	}

	err = user.UpdateUser(server.HandlerCtx, email, &model)
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

	err := user.DeleteUser(server.HandlerCtx, email)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(200).JSON(fiber.Map{"message": "Successfully deleted user"})
}
