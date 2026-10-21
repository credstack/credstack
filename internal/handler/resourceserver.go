package handler

import (
	"strconv"

	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/pkg/oauth/resourceserver"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gofiber/fiber/v3"
)

type ResourceServerRouteHandler struct {
	// server - Dependencies required by all API handlers
	server *server.Server

	// group - The Fiber API group for this service
	group fiber.Router
}

func (svc *ResourceServerRouteHandler) Group() fiber.Router {
	return svc.group
}

func (svc *ResourceServerRouteHandler) RegisterHandlers() {
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
func (svc *ResourceServerRouteHandler) GetResourceServerHandler(c fiber.Ctx) error {
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
func (svc *ResourceServerRouteHandler) PostResourceServerHandler(c fiber.Ctx) error {
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
func (svc *ResourceServerRouteHandler) PatchResourceServerHandler(c fiber.Ctx) error {
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
func (svc *ResourceServerRouteHandler) DeleteResourceServerHandler(c fiber.Ctx) error {
	audience := c.Query("audience")

	err := resourceserver.Delete(svc.server, audience)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(201).JSON(&fiber.Map{"message": "Deleted API successfully"})
}

func NewResourceServerRouteHandler(server *server.Server, app *fiber.App) *ResourceServerRouteHandler {
	return &ResourceServerRouteHandler{
		server: server,
		group:  app.Group("/resource_server"),
	}
}
