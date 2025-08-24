package wellknown

import (
	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/pkg/oauth/jwk"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gofiber/fiber/v3"
)

/*
GetJWKHandler - Provides a Fiber handler for processing a GET request to /.well-known/jwks.json. This should
not be called directly, and should only ever be passed to Fiber
*/
func GetJWKHandler(c fiber.Ctx) error {
	jwks, err := jwk.JWKS(server.HandlerCtx)
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.JSON(jwks)
}
