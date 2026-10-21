package handler

import (
	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/pkg/models/request"
	"github.com/credstack/credstack/pkg/oauth/flow"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
)

type OAuthRouteHandler struct {
	// server - Dependencies required by all API handlers
	server *server.Server

	// group - The Fiber API group for this service
	group fiber.Router
}

func (svc *OAuthRouteHandler) Group() fiber.Router {
	return svc.group
}

func (svc *OAuthRouteHandler) RegisterHandlers() {
	svc.group.Get("/token", svc.GetTokenHandler)
}

/*
GetTokenHandler - Provides a fiber handler for processing a GET request to /oauth2/token This should
not be called directly, and should only ever be passed to fiber
*/
func (svc *OAuthRouteHandler) GetTokenHandler(c fiber.Ctx) error {
	req := new(request.TokenRequest)

	if err := c.Bind().Query(req); err != nil {
		return middleware.HandleError(c, err)
	}

	resp, err := flow.IssueTokenForFlow(svc.server, req, viper.GetString("issuer"))
	if err != nil {
		return middleware.HandleError(c, err)
	}

	return c.JSON(resp)
}

func NewOAuthRouteHandler(server *server.Server, app *fiber.App) *OAuthRouteHandler {
	return &OAuthRouteHandler{
		server: server,
		group:  app.Group("/oauth"),
	}
}
