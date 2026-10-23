package handler

import (
	"strconv"

	"github.com/credstack/credstack/internal/middleware"
	"github.com/credstack/credstack/pkg/models/request"
	"github.com/credstack/credstack/pkg/server"
	"github.com/credstack/credstack/pkg/user"
	"github.com/gin-gonic/gin"
)

type UserRouteHandler struct {
	// server - Dependencies required by all API handlers
	server *server.Server
}

func (svc *UserRouteHandler) Prefix() string {
	return "/usr"
}

func (svc *UserRouteHandler) Group(engine *gin.Engine) {
	group := engine.Group("/user")

	group.GET("/", svc.GetUserHandler())
	group.POST("/", svc.PostUserHandler())
	group.PATCH("/", svc.PatchUserHandler())
	group.DELETE("/", svc.DeleteUserHandler())
}

// GetUserHandler Provides a Gin handler for processing a get request to /user. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (svc *UserRouteHandler) GetUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		email := c.Query("email")
		if email == "" {
			limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
			if err != nil {
				middleware.HandleError(c, err)
			}

			users, err := user.List(svc.server, limit, false)
			if err != nil {
				middleware.HandleError(c, err)
			}

			c.JSON(200, users)
		}

		requestedUser, err := user.Get(svc.server, email, false)
		if err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, requestedUser)

	}
}

// PostUserHandler - Provides a Gin handler for processing a POST request to /user This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (svc *UserRouteHandler) PostUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		registerRequest := new(request.UserRegisterRequest)

		if err := c.BindJSON(registerRequest); err != nil {
			middleware.HandleError(c, err)
		}

		err := user.Register(
			svc.server,
			svc.server.Config.CredentialConfig,
			registerRequest.Email,
			registerRequest.Username,
			registerRequest.Password,
		)

		if err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, gin.H{"message": "User successfully registered"})
	}
}

// PatchUserHandler Provides a Gin handler for processing a PATCH request to /user. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (svc *UserRouteHandler) PatchUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {

		model := new(user.User)
		if err := c.BindJSON(model); err != nil {
			middleware.HandleError(c, err)
		}

		if err := user.Update(svc.server, c.Query("email"), model); err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, gin.H{"message": "Updated user successfully"})
	}
}

// DeleteUserHandler Provides a Gin handler for processing a DELETE request to /user. This should
// not be called directly
//
// TODO: Authentication handler needs to happen here
func (svc *UserRouteHandler) DeleteUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := user.Delete(svc.server, c.Query("email")); err != nil {
			middleware.HandleError(c, err)
		}

		c.JSON(200, gin.H{"message": "Successfully deleted user"})
	}
}

func NewUserRouteHandler(server *server.Server) *UserRouteHandler {
	return &UserRouteHandler{
		server: server,
	}
}
