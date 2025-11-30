package service

import (
	"strconv"

	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/internal/server"
	"github.com/credstack/credstack/pkg/oauth/client"
	"github.com/gofiber/fiber/v3"
)

type ClientService struct {
	// server - Dependencies required by all API handlers
	server *server.Server

	// group - The Fiber API group for this service
	group fiber.Router
}

func (svc *ClientService) Group() fiber.Router {
	return svc.group
}

func (svc *ClientService) RegisterHandlers() {
	svc.group.Get("", svc.GetClientHandler)
	svc.group.Post("", svc.PostClientHandler)
	svc.group.Patch("", svc.PatchClientHandler)
	svc.group.Delete("", svc.DeleteClientHandler)
}

/*
GetClientHandler - Provides a Fiber handler for processing a get request to /client. This should
not be called directly, and should only ever be passed to Fiber

TODO: Authentication handler needs to happen here
*/
func (svc *ClientService) GetClientHandler(c fiber.Ctx) error {
	clientId := c.Query("client_id")
	if clientId == "" {
		limit, err := strconv.Atoi(c.Query("limit", "10"))
		if err != nil {
			return middleware.HandleError(c, err)
		}

		apps, err := client.List(svc.server, limit, true)
		if err != nil {
			return middleware.HandleError(c, err)
		}

		return c.JSON(apps)
	}

	app, err := client.Get(svc.server, clientId, true)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.JSON(app)
}

/*
PostClientHandler - Provides a fiber handler for processing a POST request to /client This should
not be called directly, and should only ever be passed to fiber

TODO: Authentication handler needs to happen here
*/
func (svc *ClientService) PostClientHandler(c fiber.Ctx) error {
	var model client.Client

	err := middleware.BindJSON(c, &model)
	if err != nil {
		return err
	}

	clientId, err := client.New(svc.server, model.Name, model.IsPublic, model.GrantTypes...)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(201).JSON(&fiber.Map{"message": "Created application successfully", "client_id": clientId})
}

/*
PatchClientHandler - Provides a fiber handler for processing a PATCH request to /client This should
not be called directly, and should only ever be passed to fiber

TODO: Authentication handler needs to happen here
*/
func (svc *ClientService) PatchClientHandler(c fiber.Ctx) error {
	clientId := c.Query("client_id")

	var model client.Client

	err := middleware.BindJSON(c, &model)
	if err != nil {
		return err
	}

	err = client.Update(svc.server, clientId, &model)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(200).JSON(&fiber.Map{"message": "Updated application successfully"})
}

/*
DeleteClientHandler - Provides a fiber handler for processing a DELETE request to /client This should
not be called directly, and should only ever be passed to fiber

TODO: Authentication handler needs to happen here
*/
func (svc *ClientService) DeleteClientHandler(c fiber.Ctx) error {
	clientId := c.Query("client_id")

	err := client.Delete(svc.server, clientId)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.Status(200).JSON(&fiber.Map{"message": "Deleted application successfully"})
}

func NewClientService(server *server.Server, app *fiber.App) *ClientService {
	return &ClientService{
		server: server,
		group:  app.Group("/client"),
	}
}
