package api

import "github.com/gofiber/fiber/v3"

/*
IService - Interface for all API Services to implement from
*/
type IService interface {
	// Group - Returns a pointer to the fiber group controlling the services handlers
	Group() fiber.Router

	// RegisterHandlers - Registers routes for Fiber and associates them with their handlers
	RegisterHandlers()
}
