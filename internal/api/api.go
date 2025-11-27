package api

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/credstack/credstack/internal/handlers/auth"
	"github.com/credstack/credstack/internal/handlers/management"
	"github.com/credstack/credstack/internal/handlers/oauth"
	"github.com/credstack/credstack/internal/handlers/wellknown"
	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/internal/server"
	"github.com/gofiber/fiber/v3"
)

type Api struct {
	// fiberConfig - Fiber's configuration values
	fiberConfig *fiber.Config

	// listenConfig - Fiber's listener configuration values
	listenConfig *fiber.ListenConfig

	// app - An instance of a Fiber Application
	app *fiber.App

	// server - Dependencies required by all API handlers
	server *server.Server
}

/*
AddRoutes - Add's routes to the api.app global that is provided
*/
func (api *Api) AddRoutes() {
	/*
		Application Routes - /management/application
	*/
	api.app.Get("/management/application", middleware.LogMiddleware, management.GetApplicationHandler)
	api.app.Post("/management/application", middleware.LogMiddleware, management.PostApplicationHandler)
	api.app.Patch("/management/application", middleware.LogMiddleware, management.PatchApplicationHandler)
	api.app.Delete("/management/application", middleware.LogMiddleware, management.DeleteApplicationHandler)

	/*
		API Routes - /management/api
	*/
	api.app.Get("/management/api", middleware.LogMiddleware, management.GetAPIHandler)
	api.app.Post("/management/api", middleware.LogMiddleware, management.PostAPIHandler)
	api.app.Patch("/management/api", middleware.LogMiddleware, management.PatchAPIHandler)
	api.app.Delete("/management/api", middleware.LogMiddleware, management.DeleteAPIHandler)

	/*
		User Routes - /management/user
	*/
	api.app.Get("/management/user", middleware.LogMiddleware, management.GetUserHandler)
	api.app.Patch("/management/user", middleware.LogMiddleware, management.PatchUserHandler)
	api.app.Delete("/management/user", middleware.LogMiddleware, management.DeleteUserHandler)

	/*
		Internal Authentication - /auth/*
	*/
	api.app.Post("/auth/register", middleware.LogMiddleware, auth.RegisterUserHandler)

	/*
		OAuth Handlers - /oauth2/*
	*/

	api.app.Get("/oauth/token", middleware.LogMiddleware, oauth.GetTokenHandler)
	/*
		Well Known Handlers
	*/
	api.app.Get("/.well-known/jwks.json", middleware.LogMiddleware, wellknown.GetJWKHandler)
}

/*
Start - Connects to MongoDB and starts the API
*/
func (api *Api) Start(ctx context.Context, port int) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)

	err := api.server.Start() // this needs to go.
	if err != nil {
		return err
	}

	go func() {
		err := api.app.Listen(":"+strconv.Itoa(port), *api.listenConfig)
		if err != nil {
			// Handle Error
		}

		api.server.Log().LogStartupEvent("API", "API is now listening for requests on port "+strconv.Itoa(port))
	}()

	<-quit

	err = api.Stop(ctx)
	if err != nil {
		return err
	}

	err = api.server.Stop()
	if err != nil {
		return err
	}

	return nil
}

/*
Stop - Gracefully terminates the API, closes database connections and flushes existing logs to sync
*/
func (api *Api) Stop(ctx context.Context) error {
	api.server.Log().LogShutdownEvent("API", "Shutting down API. New requests will not be allowed")

	/*
		First we shut down the API to ensure that any currently processing requests
		finish. Additionally, we don't want new requests coming in as we are shutting
		down the server
	*/
	err := api.app.ShutdownWithContext(ctx)
	if err != nil {
		return err // log here
	}

	return nil
}

/*
New - Constructs a new fiber.api.app with recommended configurations
*/
func New() *Api {
	// these should eventually be exposed to the user

	config := &fiber.Config{
		CaseSensitive: true,
		StrictRouting: true,
		AppName:       "CredStack API",
	}

	listenConfig := fiber.ListenConfig{
		DisableStartupMessage: true,
		EnablePrefork:         false, // this makes log entries duplicate; need better support for multiple processes
		ListenerNetwork:       "tcp4",
	}

	api := &Api{
		fiberConfig:  config,
		listenConfig: &listenConfig,
		app:          fiber.New(*config),
	}
	api.AddRoutes() // todo: Fix this; Code smell

	return api
}
