package handlers

import (
	"strconv"

	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/internal/server"
	"github.com/credstack/credstack/pkg/oauth/api"
	"github.com/gofiber/fiber/v3"
)

type ApiService struct {
	// server - Dependencies required by all API handlers
	server *server.Server

	// group - The Fiber API group for this service
	group fiber.Router
}

func (svc *ApiService) Group() fiber.Router {
	return svc.group
}

func (svc *ApiService) RegisterHandlers() {
	svc.group.Get("", svc.GetAPIHandler)
	svc.group.Post("", svc.PostAPIHandler)
	svc.group.Patch("", svc.PatchAPIHandler)
	svc.group.Delete("", svc.DeleteAPIHandler)
}

/*
GetAPIHandler - Provides a Fiber handler for processing a GET request to /management/api. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func (svc *ApiService) GetAPIHandler(c fiber.Ctx) error {
	audience := c.Query("audience")
	if audience == "" {
		limit, err := strconv.Atoi(c.Query("limit", "10"))
		if err != nil {
			return middleware.HandleError(c, err)
		}

		apis, err := api.List(svc.server, limit)
		if err != nil {
			return middleware.HandleError(c, err)
		}

		return c.JSON(apis)
	}

	requestedApi, err := api.Get(svc.server, audience)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.JSON(requestedApi)
}

/*
PostAPIHandler - Provides a Fiber handler for processing a POST request to /management/api. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
TODO: Underlying functions need domain validation in place
TODO: Underlying functions need to be updated here so that we can assign applications at birth
*/
func (svc *ApiService) PostAPIHandler(c fiber.Ctx) error {
	var model api.Api

	err := middleware.BindJSON(c, &model)
	if err != nil {
		return err
	}

	err = api.New(svc.server, model.Name, model.Audience, model.TokenType)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(201).JSON(&fiber.Map{"message": "Created API successfully"})
}

/*
PatchAPIHandler - Provides a Fiber handler for processing a PATCH request to /management/api. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func (svc *ApiService) PatchAPIHandler(c fiber.Ctx) error {
	audience := c.Query("audience")

	var model api.Api

	err := middleware.BindJSON(c, &model)
	if err != nil {
		return err
	}

	err = api.Update(svc.server, audience, &model)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(201).JSON(&fiber.Map{"message": "Updated API successfully"})
}

/*
DeleteAPIHandler - Provides a Fiber handler for processing a DELETE request to /management/api. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func (svc *ApiService) DeleteAPIHandler(c fiber.Ctx) error {
	audience := c.Query("audience")

	err := api.Delete(svc.server, audience)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(201).JSON(&fiber.Map{"message": "Deleted API successfully"})
}

func NewApiService(server *server.Server, app *fiber.App) *ApiService {
	return &ApiService{
		server: server,
		group:  app.Group("/api"),
	}
}
