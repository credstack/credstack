package api

import (
	"context"
	"strconv"

	"github.com/credstack/credstack/internal/handlers/auth"
	"github.com/credstack/credstack/internal/handlers/management"
	"github.com/credstack/credstack/internal/handlers/oauth"
	"github.com/credstack/credstack/internal/handlers/wellknown"
	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gofiber/fiber/v3"
)

// App - A global variable that provides interaction with the Fiber Application
var App *fiber.App

/*
AddRoutes - Add's routes to the App global that is provided
*/
func AddRoutes() {
	/*
		Application Routes - /management/application
	*/
	App.Get("/management/application", middleware.LogMiddleware, management.GetApplicationHandler)
	App.Post("/management/application", middleware.LogMiddleware, management.PostApplicationHandler)
	App.Patch("/management/application", middleware.LogMiddleware, management.PatchApplicationHandler)
	App.Delete("/management/application", middleware.LogMiddleware, management.DeleteApplicationHandler)

	/*
		API Routes - /management/api
	*/
	App.Get("/management/api", middleware.LogMiddleware, management.GetAPIHandler)
	App.Post("/management/api", middleware.LogMiddleware, management.PostAPIHandler)
	App.Patch("/management/api", middleware.LogMiddleware, management.PatchAPIHandler)
	App.Delete("/management/api", middleware.LogMiddleware, management.DeleteAPIHandler)

	/*
		User Routes - /management/user
	*/
	App.Get("/management/user", middleware.LogMiddleware, management.GetUserHandler)
	App.Patch("/management/user", middleware.LogMiddleware, management.PatchUserHandler)
	App.Delete("/management/user", middleware.LogMiddleware, management.DeleteUserHandler)

	/*
		Internal Authentication - /auth/*
	*/
	App.Post("/auth/register", middleware.LogMiddleware, auth.RegisterUserHandler)

	/*
		OAuth Handlers - /oauth2/*
	*/

	App.Get("/oauth/token", middleware.LogMiddleware, oauth.GetTokenHandler)
	/*
		Well Known Handlers
	*/
	App.Get("/.well-known/jwks.json", middleware.LogMiddleware, wellknown.GetJWKHandler)
}

/*
New - Constructs a new fiber.App with recommended configurations
*/
func New() *fiber.App {
	/*
		Realistically, these should probably be exposed to the user for them to modify,
		however they are hardcoded for now to ensure that these will ensure the most performance
	*/
	config := fiber.Config{
		CaseSensitive: true,
		StrictRouting: true,
		AppName:       "CredStack API",
	}

	app := fiber.New(config)

	return app
}

/*
Start - Connects to MongoDB and starts the API
*/
func Start(port int) error {
	/*
		Realistically, these should probably be exposed to the user for them to modify,
		however they are hardcoded for now to ensure that these will ensure the most performance
	*/
	listenConfig := fiber.ListenConfig{
		DisableStartupMessage: true,
		EnablePrefork:         false, // this makes log entries duplicate
		ListenerNetwork:       "tcp4",
	}

	/*
		Once our database is connected we can properly start our API
	*/
	server.HandlerCtx.Log().LogStartupEvent("API", "API is now listening for requests on port "+strconv.Itoa(port))
	err := App.Listen(":"+strconv.Itoa(port), listenConfig)
	if err != nil {
		return err // log here
	}

	return nil
}

/*
Stop - Gracefully terminates the API, closes database connections and flushes existing logs to sync
*/
func Stop(ctx context.Context) error {
	server.HandlerCtx.Log().LogShutdownEvent("API", "Shutting down API. New requests will not be allowed")

	/*
		First we shut down the API to ensure that any currently processing requests
		finish. Additionally, we don't want new requests coming in as we are shutting
		down the server
	*/
	err := App.ShutdownWithContext(ctx)
	if err != nil {
		return err // log here
	}

	return nil
}
