package handler

import (
	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/internal/server"
	"github.com/credstack/credstack/internal/services/oauth/jwk"
	"github.com/gin-gonic/gin"
)

type WellKnownRouteHandler struct {
	// server Dependencies required by all API handlers
	server *server.Server

	// jwkService Service for interacting with JWK/JWKS
	jwkService *jwk.Service
}

func (handler *WellKnownRouteHandler) Prefix() string {
	return "/.well-known"
}

func (handler *WellKnownRouteHandler) Group(engine *gin.Engine) {
	group := engine.Group(handler.Prefix())
	group.GET("/jwks.json", handler.GetJWKHandler())
}

// GetJWKHandler Provides a gin.HandlerFunc for `/.well-known/jwks.json`. Should not be called directly
func (handler *WellKnownRouteHandler) GetJWKHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwks, err := handler.jwkService.JWKS(c.Request.Context())
		if err != nil {
			middleware.HandleError(c, err)
			return
		}

		c.JSON(200, jwks)
	}
}

// NewWellKnownRouteHandler Initializes a new WellKnownRouteHandler and returns a pointer to it
func NewWellKnownRouteHandler(server *server.Server) *WellKnownRouteHandler {
	return &WellKnownRouteHandler{
		server:     server,
		jwkService: jwk.New(server),
	}
}
