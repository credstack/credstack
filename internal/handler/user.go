package handler

import (
	"strconv"

	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/internal/services/user"
	"github.com/credstack/credstack/pkg/models/request"
	userModel "github.com/credstack/credstack/pkg/models/user"
	"github.com/credstack/credstack/pkg/server"
	"github.com/gin-gonic/gin"
)

type UserRouteHandler struct {
	// server Dependencies required by all API handlers
	server *server.Server

	// svc The user service
	svc *user.Service
}

func (handler *UserRouteHandler) Prefix() string {
	return "/usr"
}

func (handler *UserRouteHandler) Group(engine *gin.Engine) {
	group := engine.Group("/user")

	group.GET("/", handler.GetUserHandler())
	group.POST("/", handler.PostUserHandler())
	group.PATCH("/", handler.PatchUserHandler())
	group.DELETE("/", handler.DeleteUserHandler())
}

// GetUserHandler Provides a Gin handler for processing a get request to /user. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (handler *UserRouteHandler) GetUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		email := c.Query("email")
		if email == "" {
			limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
			if err != nil {
				middleware.HandleError(c, err)
				return
			}

			users, err := handler.svc.List(c.Request.Context(), limit)
			if err != nil {
				middleware.HandleError(c, err)
				return
			}

			c.JSON(200, users)
			return
		}

		requestedUser, err := handler.svc.Get(c.Request.Context(), email)
		if err != nil {
			middleware.HandleError(c, err)
			return
		}

		c.JSON(200, requestedUser)

	}
}

// PostUserHandler - Provides a Gin handler for processing a POST request to /user This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (handler *UserRouteHandler) PostUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		registerRequest := new(request.UserRegisterRequest)

		if err := c.BindJSON(registerRequest); err != nil {
			middleware.HandleError(c, err)
			return
		}

		if err := handler.svc.Register(c.Request.Context(), registerRequest); err != nil {
			middleware.HandleError(c, err)
			return
		}

		c.JSON(200, gin.H{"message": "User successfully registered"})
	}
}

// PatchUserHandler Provides a Gin handler for processing a PATCH request to /user. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (handler *UserRouteHandler) PatchUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		model := new(userModel.User)
		if err := c.BindJSON(model); err != nil {
			middleware.HandleError(c, err)
			return
		}

		if err := handler.svc.Update(c.Request.Context(), c.Query("email"), model); err != nil {
			middleware.HandleError(c, err)
			return
		}

		c.JSON(200, gin.H{"message": "Updated user successfully"})
	}
}

// DeleteUserHandler Provides a Gin handler for processing a DELETE request to /user. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (handler *UserRouteHandler) DeleteUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := handler.svc.Delete(c.Request.Context(), c.Query("email")); err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, gin.H{"message": "Successfully deleted user"})
	}
}

func NewUserRouteHandler(server *server.Server) *UserRouteHandler {
	return &UserRouteHandler{
		server: server,
		svc:    user.New(server),
	}
}
