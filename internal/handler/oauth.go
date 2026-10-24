package handler

import (
	"errors"

	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/internal/services/oauth/flow"
	"github.com/credstack/credstack/pkg/models/request"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gin-gonic/gin"
)

type OAuthRouteHandler struct {
	// server - Dependencies required by all API handlers
	server *server.Server

	svc *flow.Service
}

// Prefix Returns the parent prefix of all routes this Handler provides
func (handler *OAuthRouteHandler) Prefix() string {
	return "/oauth"
}

// Group Registers the endpoints this Handler provides with Gin
func (handler *OAuthRouteHandler) Group(engine *gin.Engine) {
	group := engine.Group(handler.Prefix())

	group.GET("/token", handler.GetTokenHandler())
}

/*
GetTokenHandler - Provides a fiber handler for processing a GET request to /oauth2/token This should
not be called directly, and should only ever be passed to fiber
*/
func (handler *OAuthRouteHandler) GetTokenHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		req := new(request.TokenRequest)

		if err := c.BindQuery(req); err != nil {
			middleware.HandleError(c, err)
			return
		}

		resp, err := handler.svc.IssueToken(c.Request.Context(), req)
		if err != nil {
			if errors.Is(err, flow.ErrInvalidClientCredentials) {
				c.AbortWithStatusJSON(401, gin.H{"error": "Invalid client credentials provided for 'client_credentials' flow"})
				return
			}

			middleware.HandleError(c, err)
			return
		}

		c.JSON(200, resp)
	}
}

func NewOAuthRouteHandler(server *server.Server) *OAuthRouteHandler {
	return &OAuthRouteHandler{
		server: server,
		svc:    flow.New(server),
	}
}
