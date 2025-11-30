package api

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/credstack/credstack/internal/server"
	"github.com/credstack/credstack/internal/service"
	"github.com/credstack/credstack/pkg/options"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/pprof"
	"github.com/gofiber/fiber/v3/middleware/recover"
)

type Api struct {
	// options - Universal options for the API
	options *options.ApiOptions

	// app - An instance of a Fiber Application
	app *fiber.App

	// server - Dependencies required by all API handlers
	server *server.Server
}

func (api *Api) RegisterHandlers() {
	service.NewUserService(api.server, api.app).RegisterHandlers()
	service.NewClientService(api.server, api.app).RegisterHandlers()
	service.NewResourceServerService(api.server, api.app).RegisterHandlers()
	service.NewOAuthService(api.server, api.app).RegisterHandlers()
	service.NewWellKnownService(api.server, api.app).RegisterHandlers()
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

	err = api.server.Stop()
	if err != nil {
		return err
	}

	return nil
}

/*
Start - Connects to MongoDB and starts the API
*/
func (api *Api) Start(ctx context.Context) error {
	err := api.server.Start() // this needs to go.
	if err != nil {
		return err
	}

	api.RegisterHandlers()

	errChan := make(chan error, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)
	go func() {
		select {
		case <-ctx.Done():
			return
		default:
			api.server.Log().LogStartupEvent("API", "API is now listening for requests on port "+strconv.Itoa(api.options.Port))
			err := api.app.Listen(":"+strconv.Itoa(api.options.Port), api.options.ListenerConfig())
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-quit:
		err = api.Stop(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

/*
New - Constructs a new fiber.api.app with recommended configurations
*/
func New(options *options.ApiOptions) *Api {
	app := fiber.New(options.FiberConfig())

	// recovery middleware is always added to ensure that the API does not crash due to a stray panic
	app.Use(
		recover.New(),
	)

	// only register pprof if options.debug == true
	if options.Debug {
		app.Use(
			pprof.New(),
		)
	}

	api := &Api{
		options: options,
		server:  server.FromConfig(),
		app:     app,
	}

	return api
}
