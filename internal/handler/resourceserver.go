package handler

import (
	"strconv"

	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/pkg/oauth/resourceserver"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gin-gonic/gin"
)

type ResourceServerRouteHandler struct {
	// server - Dependencies required by all API handlers
	server *server.Server
}

func (handler *ResourceServerRouteHandler) Prefix() string {
	return "/resource_server"
}

func (handler *ResourceServerRouteHandler) Group(engine *gin.Engine) {
	group := engine.Group(handler.Prefix())

	group.GET("/", handler.GetResourceServerHandler())
	group.POST("/", handler.PostResourceServerHandler())
	group.PATCH("/", handler.PatchResourceServerHandler())
	group.DELETE("/", handler.DeleteResourceServerHandler())
}

// GetResourceServerHandler - Provides a Gin handler for processing a GET request to /management/api. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (handler *ResourceServerRouteHandler) GetResourceServerHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		audience := c.Query("audience")
		if audience == "" {
			limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
			if err != nil {
				middleware.HandleError(c, err)
			}

			apis, err := resourceserver.List(handler.server, limit)
			if err != nil {
				middleware.HandleError(c, err)
			}

			c.JSON(200, apis)
		}

		requestedApi, err := resourceserver.Get(handler.server, audience)
		if err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, requestedApi)
	}
}

// PostResourceServerHandler - Provides a Gin handler for processing a POST request to /management/api. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
// TODO: Better object validation
func (handler *ResourceServerRouteHandler) PostResourceServerHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		model := new(resourceserver.ResourceServer)

		if err := c.BindJSON(model); err != nil {
			middleware.HandleError(c, err)
		}

		if err := resourceserver.New(handler.server, model.Name, model.Audience, model.TokenType); err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, gin.H{"message": "Created API successfully"})
	}
}

// PatchResourceServerHandler - Provides a Gin handler for processing a PATCH request to /management/api. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (handler *ResourceServerRouteHandler) PatchResourceServerHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		model := new(resourceserver.ResourceServer)
		if err := c.BindJSON(model); err != nil {
			middleware.HandleError(c, err)
		}

		if err := resourceserver.Update(handler.server, c.Query("audience"), model); err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, gin.H{"message": "Updated API successfully"})
	}
}

// DeleteResourceServerHandler - Provides a Gin handler for processing a DELETE request to /management/api. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (handler *ResourceServerRouteHandler) DeleteResourceServerHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := resourceserver.Delete(handler.server, c.Query("audience")); err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, gin.H{"message": "Deleted API successfully"})
	}
}

func NewResourceServerRouteHandler(server *server.Server) *ResourceServerRouteHandler {
	return &ResourceServerRouteHandler{
		server: server,
	}
}
