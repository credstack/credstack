package management

import (
	"github.com/credstack/credstack/internal/middleware"
	applicationModel "github.com/credstack/credstack/pkg/models/application"
	"github.com/credstack/credstack/pkg/oauth/application"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gofiber/fiber/v3"
	"strconv"
)

/*
GetApplicationHandler - Provides a Fiber handler for processing a get request to /management/application. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func GetApplicationHandler(c fiber.Ctx) error {
	clientId := c.Query("client_id")
	if clientId == "" {
		limit, err := strconv.Atoi(c.Query("limit", "10"))
		if err != nil {
			return middleware.HandleError(c, err)
		}

		apps, err := application.ListApplication(server.HandlerCtx, limit, true)
		if err != nil {
			return middleware.HandleError(c, err)
		}

		return middleware.MarshalProtobufList(c, apps)
	}

	app, err := application.GetApplication(server.HandlerCtx, clientId, true)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return middleware.MarshalProtobuf(c, app)
}

/*
PostApplicationHandler - Provides a fiber handler for processing a POST request to /management/application This should
not be called directly, and should only ever be passed to fiber

TODO: Authentication handler needs to happen here
*/
func PostApplicationHandler(c fiber.Ctx) error {
	var model applicationModel.Application

	err := middleware.BindJSON(c, &model)
	if err != nil {
		return err
	}

	clientId, err := application.NewApplication(server.HandlerCtx, model.Name, model.IsPublic, model.GrantType...)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(201).JSON(&fiber.Map{"message": "Created application successfully", "client_id": clientId})
}

/*
PatchApplicationHandler - Provides a fiber handler for processing a PATCH request to /management/application This should
not be called directly, and should only ever be passed to fiber

TODO: Authentication handler needs to happen here
*/
func PatchApplicationHandler(c fiber.Ctx) error {
	clientId := c.Query("client_id")

	var model applicationModel.Application

	err := middleware.BindJSON(c, &model)
	if err != nil {
		return err
	}

	err = application.UpdateApplication(server.HandlerCtx, clientId, &model)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(200).JSON(&fiber.Map{"message": "Updated application successfully"})
}

/*
DeleteApplicationHandler - Provides a fiber handler for processing a DELETE request to /management/application This should
not be called directly, and should only ever be passed to fiber

TODO: Authentication handler needs to happen here
*/
func DeleteApplicationHandler(c fiber.Ctx) error {
	clientId := c.Query("client_id")

	err := application.DeleteApplication(server.HandlerCtx, clientId)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(200).JSON(&fiber.Map{"message": "Deleted application successfully"})
}
