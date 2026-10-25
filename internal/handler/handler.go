package handler

import "github.com/gin-gonic/gin"

// RouteHandler Represents a struct containing Gin handlers
type RouteHandler interface {
	// Prefix The prefix of the route that contains your handlers (i.e. `/ok`)
	Prefix() string

	// Group Represents the router group that this RouteHandler serves
	Group(*gin.Engine)
}
