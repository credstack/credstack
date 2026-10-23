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

func (handler *ClientRouteHandler) Prefix() string {
	return "/client"
}

func (handler *ClientRouteHandler) Group(engine *gin.Engine) {
	group := engine.Group(handler.Prefix())

	group.GET("/", handler.GetClientHandler())
	group.POST("/", handler.PostClientHandler())
	group.PATCH("/", handler.PatchClientHandler())
	group.DELETE("/", handler.DeleteClientHandler())
}

// GetClientHandler - Provides a Gin handler for processing a get request to /client. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (handler *ClientRouteHandler) GetClientHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientId := c.Query("client_id")
		if clientId == "" {
			limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
			if err != nil {
				middleware.HandleError(c, err)
			}

			apps, err := client.List(handler.server, limit, true)
			if err != nil {
				middleware.HandleError(c, err)
			}

			c.JSON(200, apps)
		}

		app, err := client.Get(handler.server, clientId, true)
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
func (handler *ClientRouteHandler) PostClientHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		model := new(client.Client)
		if err := c.BindJSON(model); err != nil {
			middleware.HandleError(c, err)
		}

		clientId, err := client.New(handler.server, model.Name, model.IsPublic, model.GrantTypes...)
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
func (handler *ClientRouteHandler) PatchClientHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		model := new(client.Client)
		if err := c.BindJSON(model); err != nil {
			middleware.HandleError(c, err)
		}

		if err := client.Update(handler.server, c.Query("client_id"), model); err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, gin.H{"message": "Updated application successfully"})
	}
}

// DeleteClientHandler - Provides a Gin handler for processing a DELETE request to /client This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (handler *ClientRouteHandler) DeleteClientHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := client.Delete(handler.server, c.Query("client_id")); err != nil {
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
