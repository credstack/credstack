package wellknown

import (
	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/internal/server"
	"github.com/credstack/credstack/pkg/oauth/jwk"
	"github.com/gofiber/fiber/v3"
)

type WellKnownService struct {
	// server - Dependencies required by all API handlers
	server *server.Server

	// group - The Fiber API group for this service
	group fiber.Router
}

func (svc *WellKnownService) Group() fiber.Router {
	return svc.group
}

func (svc *WellKnownService) RegisterHandlers() {
	svc.group.Get("/jwks.json", svc.GetJWKHandler)
}

/*
GetJWKHandler - Provides a Fiber handler for processing a GET request to /.well-known/jwks.json. This should
not be called directly, and should only ever be passed to Fiber
*/
func (svc *WellKnownService) GetJWKHandler(c fiber.Ctx) error {
	jwks, err := jwk.JWKS(svc.server)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.JSON(jwks)
}

func NewWellKnownService(server *server.Server, app *fiber.App) *WellKnownService {
	return &WellKnownService{
		server: server,
		group:  app.Group("/.well-known"),
	}
}
