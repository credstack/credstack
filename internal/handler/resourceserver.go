package handler

import (
	"strconv"

	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/internal/server"
	"github.com/credstack/credstack/internal/services/oauth/jwk"
	"github.com/credstack/credstack/internal/services/oauth/resourceserver"
	resourceServerModel "github.com/credstack/credstack/pkg/models/oauth/resourceserver"
	"github.com/gin-gonic/gin"
)

type ResourceServerRouteHandler struct {
	// server Dependencies required by all API handlers
	server *server.Server

	// svc Resource Server service
	svc *resourceserver.Service
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
				return
			}

			rs, err := handler.svc.List(c.Request.Context(), limit)
			if err != nil {
				middleware.HandleError(c, err)
				return
			}

			c.JSON(200, rs)
			return
		}

		rs, err := handler.svc.Get(c.Request.Context(), audience)
		if err != nil {
			middleware.HandleError(c, err)
			return
		}

		c.JSON(200, rs)
	}
}

// PostResourceServerHandler - Provides a Gin handler for processing a POST request to /management/api. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
// TODO: Better object validation
func (handler *ResourceServerRouteHandler) PostResourceServerHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		model := new(resourceServerModel.ResourceServer)

		if err := c.BindJSON(model); err != nil {
			middleware.HandleError(c, err)
		}

		if err := handler.svc.New(c.Request.Context(), model); err != nil {
			middleware.HandleError(c, err)
			return
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
		model := new(resourceServerModel.ResourceServer)
		if err := c.BindJSON(model); err != nil {
			middleware.HandleError(c, err)
			return
		}

		if err := handler.svc.Update(c.Request.Context(), c.Query("audience"), model); err != nil {
			middleware.HandleError(c, err)
			return
		}

		c.JSON(200, gin.H{"message": "Updated API successfully"})
	}
}

// DeleteResourceServerHandler - Provides a Gin handler for processing a DELETE request to /management/api. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
// TODO: This is returning 200 even when no resource server is found
func (handler *ResourceServerRouteHandler) DeleteResourceServerHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := handler.svc.Delete(c.Request.Context(), c.Query("audience")); err != nil {
			middleware.HandleError(c, err)
			return
		}

		c.JSON(200, gin.H{"message": "Deleted API successfully"})
	}
}

func NewResourceServerRouteHandler(server *server.Server) *ResourceServerRouteHandler {
	return &ResourceServerRouteHandler{
		server: server,
		svc:    resourceserver.New(server, jwk.New(server)),
	}
}
