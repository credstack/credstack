package handler

import (
	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/pkg/models/request"
	"github.com/credstack/credstack/pkg/oauth/flow"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type OAuthRouteHandler struct {
	// server - Dependencies required by all API handlers
	server *server.Server
}

// Prefix Returns the parent prefix of all routes this Handler provides
func (handler *OAuthRouteHandler) Prefix() string {
	return "/oauth"
}

// Group Registers the endpoints this Handler provides with Gin
func (svc *OAuthRouteHandler) Group(engine *gin.Engine) {
	group := engine.Group(svc.Prefix())

	group.GET("/token", svc.GetTokenHandler())
}

/*
GetTokenHandler - Provides a fiber handler for processing a GET request to /oauth2/token This should
not be called directly, and should only ever be passed to fiber
*/
func (svc *OAuthRouteHandler) GetTokenHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		req := new(request.TokenRequest)

		if err := c.BindQuery(req); err != nil {
			middleware.HandleError(c, err)
		}

		resp, err := flow.IssueTokenForFlow(svc.server, req, viper.GetString("issuer"))
		if err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, resp)
	}
}

func NewOAuthRouteHandler(server *server.Server) *OAuthRouteHandler {
	return &OAuthRouteHandler{
		server: server,
	}
}
