package service

import (
	"strconv"

	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/internal/server"
	"github.com/credstack/credstack/pkg/models/request"
	"github.com/credstack/credstack/pkg/options"
	"github.com/credstack/credstack/pkg/user"
	"github.com/gofiber/fiber/v3"
)

type UserService struct {
	// server - Dependencies required by all API handlers
	server *server.Server

	// group - The Fiber API group for this service
	group fiber.Router
}

func (svc *UserService) Group() fiber.Router {
	return svc.group
}

/*
RegisterHandlers - Registers required handlers with the associated Fiber router
*/
func (svc *UserService) RegisterHandlers() {
	svc.group.Get("", svc.GetUserHandler)
	svc.group.Post("", svc.PostUserHandler)
	svc.group.Patch("", svc.PatchUserHandler)
	svc.group.Delete("", svc.DeleteUserHandler)
}

/*
GetUserHandler - Provides a Fiber handler for processing a get request to /management/user. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func (svc *UserService) GetUserHandler(c fiber.Ctx) error {
	email := c.Query("email")
	if email == "" {
		limit, err := strconv.Atoi(c.Query("limit", "10"))
		if err != nil {
			return middleware.HandleError(c, err)
		}

		users, err := user.List(svc.server, limit, false)
		if err != nil {
			return middleware.HandleError(c, err)
		}

		return c.JSON(users)
	}

	requestedUser, err := user.Get(svc.server, email, false)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.JSON(requestedUser)
}

/*
PostUserHandler - Provides a fiber handler for processing a POST request to /auth/register This should
not be called directly, and should only ever be passed to fiber

TODO: Authentication handler needs to happen here
*/
func (svc *UserService) PostUserHandler(c fiber.Ctx) error {
	var registerRequest request.UserRegisterRequest

	err := middleware.BindJSON(c, &registerRequest)
	if err != nil {
		return err
	}

	err = user.Register(
		svc.server,
		options.Credential().FromConfig(),
		registerRequest.Email,
		registerRequest.Username,
		registerRequest.Password,
	)

	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(200).JSON(&fiber.Map{"message": "User successfully registered"}) // this should get its own response
}

/*
PatchUserHandler - Provides a Fiber handler for processing a PATCH request to /management/user. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func (svc *UserService) PatchUserHandler(c fiber.Ctx) error {
	email := c.Query("email")

	var model user.User

	err := middleware.BindJSON(c, &model)
	if err != nil {
		return err
	}

	err = user.Update(svc.server, email, &model)
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
func (svc *UserService) DeleteUserHandler(c fiber.Ctx) error {
	email := c.Query("email")

	err := user.Delete(svc.server, email)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(200).JSON(fiber.Map{"message": "Successfully deleted user"})
}

func NewUserService(server *server.Server, app *fiber.App) *UserService {
	return &UserService{
		server: server,
		group:  app.Group("/user"),
	}
}
