package handler

import (
	"github.com/credstack/credstack/pkg/oauth/jwk"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gin-gonic/gin"
)

type WellKnownRouteHandler struct {
	// server - Dependencies required by all API handlers
	server *server.Server
}

func (svc *WellKnownRouteHandler) Prefix() string {
	return "/.well-known"
}

func (svc *WellKnownRouteHandler) Group(engine *gin.Engine) {
	group := engine.Group(svc.Prefix())

	group.GET("/jwks.json", svc.GetJWKHandler())
}

// GetJWKHandler Provides a gin.HandlerFunc for `/.well-known/jwks.json`. Should not be called directly
func (svc *WellKnownRouteHandler) GetJWKHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwks, err := jwk.JWKS(svc.server)
		if err != nil {
			c.JSON(500, err) // TODO: Real error handling here
		}

		c.JSON(200, jwks)
	}
}

// NewWellKnownRouteHandler Initializes a new WellKnownRouteHandler and returns a pointer to it
func NewWellKnownRouteHandler(server *server.Server) *WellKnownRouteHandler {
	return &WellKnownRouteHandler{
		server: server,
	}
}
