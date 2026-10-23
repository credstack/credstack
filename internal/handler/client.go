package handler

import (
	"strconv"

	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/pkg/oauth/client"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gin-gonic/gin"
)

type ClientRouteHandler struct {
	// server - Dependencies required by all API handlers
	server *server.Server
}

func (svc *ClientRouteHandler) Prefix() string {
	return "/client"
}

func (svc *ClientRouteHandler) Group(engine *gin.Engine) {
	group := engine.Group(svc.Prefix())

	group.GET("/", svc.GetClientHandler())
	group.POST("/", svc.PostClientHandler())
	group.PATCH("/", svc.PatchClientHandler())
	group.DELETE("/", svc.DeleteClientHandler())
}

// GetClientHandler - Provides a Gin handler for processing a get request to /client. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (svc *ClientRouteHandler) GetClientHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientId := c.Query("client_id")
		if clientId == "" {
			limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
			if err != nil {
				middleware.HandleError(c, err)
			}

			apps, err := client.List(svc.server, limit, true)
			if err != nil {
				middleware.HandleError(c, err)
			}

			c.JSON(200, apps)
		}

		app, err := client.Get(svc.server, clientId, true)
		if err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, app)
	}
}

/*
PostClientHandler - Provides a Gin handler for processing a POST request to /client This should
not be called directly

TODO: Authentication handler needs to happen here
*/
func (svc *ClientRouteHandler) PostClientHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		model := new(client.Client)
		if err := c.BindJSON(model); err != nil {
			middleware.HandleError(c, err)
		}

		clientId, err := client.New(svc.server, model.Name, model.IsPublic, model.GrantTypes...)
		if err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, gin.H{"message": "Created application successfully", "client_id": clientId})
	}
}

// PatchClientHandler - Provides a Gin handler for processing a PATCH request to /client This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (svc *ClientRouteHandler) PatchClientHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		model := new(client.Client)
		if err := c.BindJSON(model); err != nil {
			middleware.HandleError(c, err)
		}

		if err := client.Update(svc.server, c.Query("client_id"), model); err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, gin.H{"message": "Updated application successfully"})
	}
}

// DeleteClientHandler - Provides a Gin handler for processing a DELETE request to /client This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (svc *ClientRouteHandler) DeleteClientHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := client.Delete(svc.server, c.Query("client_id")); err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, gin.H{"message": "Deleted application successfully"})
	}
}

func NewClientRouteHandler(server *server.Server) *ClientRouteHandler {
	return &ClientRouteHandler{
		server: server,
	}
}
