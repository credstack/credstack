package api

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/credstack/credstack/internal/handlers"
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

func (api *Api) RegisterHandlers() {
	handlers.NewUserService(api.server, api.app).RegisterHandlers()
	handlers.NewApiService(api.server, api.app).RegisterHandlers()
	handlers.NewApplicationService(api.server, api.app).RegisterHandlers()
	handlers.NewOAuthService(api.server, api.app).RegisterHandlers()
	handlers.NewWellKnownService(api.server, api.app).RegisterHandlers()
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
		api.server.Log().LogStartupEvent("API", "API is now listening for requests on port "+strconv.Itoa(port))

		api.RegisterHandlers()
		err := api.app.Listen(":"+strconv.Itoa(port), *api.listenConfig)
		if err != nil {
			// Handle Error
		}

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
		server:       server.FromConfig(),
	}

	return api
}
