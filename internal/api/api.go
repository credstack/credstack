package api

import (
	"context"
	"github.com/credstack/credstack/internal/handlers/auth"
	"github.com/credstack/credstack/internal/handlers/management"
	"github.com/credstack/credstack/internal/handlers/oauth"
	"github.com/credstack/credstack/internal/handlers/wellknown"
	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gofiber/fiber/v3"
	"strconv"
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
	App.Get("/management/application", management.GetApplicationHandler, middleware.LogMiddleware)
	App.Post("/management/application", management.PostApplicationHandler, middleware.LogMiddleware)
	App.Patch("/management/application", management.PatchApplicationHandler, middleware.LogMiddleware)
	App.Delete("/management/application", management.DeleteApplicationHandler, middleware.LogMiddleware)

	/*
		API Routes - /management/api
	*/
	App.Get("/management/api", management.GetAPIHandler, middleware.LogMiddleware)
	App.Post("/management/api", management.PostAPIHandler, middleware.LogMiddleware)
	App.Patch("/management/api", management.PatchAPIHandler, middleware.LogMiddleware)
	App.Delete("/management/api", management.DeleteAPIHandler, middleware.LogMiddleware)

	/*
		User Routes - /management/user
	*/
	App.Get("/management/user", management.GetUserHandler, middleware.LogMiddleware)
	App.Patch("/management/user", management.PatchUserHandler, middleware.LogMiddleware)
	App.Delete("/management/user", management.DeleteUserHandler, middleware.LogMiddleware)

	/*
		Internal Authentication - /auth/*
	*/
	App.Post("/auth/register", auth.RegisterUserHandler, middleware.LogMiddleware)

	/*
		OAuth Handlers - /oauth2/*
	*/

	App.Get("/oauth/token", oauth.GetTokenHandler, middleware.LogMiddleware)
	/*
		Well Known Handlers
	*/
	App.Get("/.well-known/jwks.json", wellknown.GetJWKHandler, middleware.LogMiddleware)
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
