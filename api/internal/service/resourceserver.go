package service

import (
	"strconv"

	"github.com/credstack/credstack/api/internal/middleware"
	"github.com/credstack/credstack/sdk/pkg/oauth/resourceserver"
	"github.com/credstack/credstack/sdk/pkg/server"
	"github.com/gofiber/fiber/v3"
)

type ResourceServerService struct {
	// server - Dependencies required by all API handlers
	server *server.Server

	// group - The Fiber API group for this service
	group fiber.Router
}

func (svc *ResourceServerService) Group() fiber.Router {
	return svc.group
}

func (svc *ResourceServerService) RegisterHandlers() {
	svc.group.Get("", svc.GetResourceServerHandler)
	svc.group.Post("", svc.PostResourceServerHandler)
	svc.group.Patch("", svc.PatchResourceServerHandler)
	svc.group.Delete("", svc.DeleteResourceServerHandler)
}

/*
GetResourceServerHandler - Provides a Fiber handler for processing a GET request to /management/api. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func (svc *ResourceServerService) GetResourceServerHandler(c fiber.Ctx) error {
	audience := c.Query("audience")
	if audience == "" {
		limit, err := strconv.Atoi(c.Query("limit", "10"))
		if err != nil {
			return middleware.HandleError(c, err)
		}

		apis, err := resourceserver.List(svc.server, limit)
		if err != nil {
			return middleware.HandleError(c, err)
		}

		return c.JSON(apis)
	}

	requestedApi, err := resourceserver.Get(svc.server, audience)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.JSON(requestedApi)
}

/*
PostResourceServerHandler - Provides a Fiber handler for processing a POST request to /management/api. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
TODO: Underlying functions need domain validation in place
TODO: Underlying functions need to be updated here so that we can assign applications at birth
*/
func (svc *ResourceServerService) PostResourceServerHandler(c fiber.Ctx) error {
	var model resourceserver.ResourceServer

	err := middleware.BindJSON(c, &model)
	if err != nil {
		return err
	}

	err = resourceserver.New(svc.server, model.Name, model.Audience, model.TokenType)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(201).JSON(&fiber.Map{"message": "Created API successfully"})
}

/*
PatchResourceServerHandler - Provides a Fiber handler for processing a PATCH request to /management/api. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func (svc *ResourceServerService) PatchResourceServerHandler(c fiber.Ctx) error {
	audience := c.Query("audience")

	var model resourceserver.ResourceServer

	err := middleware.BindJSON(c, &model)
	if err != nil {
		return err
	}

	err = resourceserver.Update(svc.server, audience, &model)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(201).JSON(&fiber.Map{"message": "Updated API successfully"})
}

/*
DeleteResourceServerHandler - Provides a Fiber handler for processing a DELETE request to /management/api. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func (svc *ResourceServerService) DeleteResourceServerHandler(c fiber.Ctx) error {
	audience := c.Query("audience")

	err := resourceserver.Delete(svc.server, audience)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(201).JSON(&fiber.Map{"message": "Deleted API successfully"})
}

func NewResourceServerService(server *server.Server, app *fiber.App) *ResourceServerService {
	return &ResourceServerService{
		server: server,
		group:  app.Group("/resource_server"),
	}
}
