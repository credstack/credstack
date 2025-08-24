package middleware

import (
	"os"

	"github.com/credstack/credstack/pkg/server"
	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
)

/*
LogMiddleware - Logs all requests before they hit its respective middleware handler
*/
func LogMiddleware(c fiber.Ctx) error {
	/*
		Only some basic HTTP request logging is provided here. Ideally, this API would be placed behind either
		a reverse proxy or a CDN (Content Delivery Network), as this would provide you more in-depth logging
	*/
	server.HandlerCtx.Log().Logger().Info(
		"HTTPRequest",
		zap.Int("pid", os.Getpid()),
		zap.String("method", c.Method()),
		zap.String("url", c.OriginalURL()),
		zap.String("request_uri", c.Path()),
		zap.String("client_ip", c.IP()),
		zap.Bool("is_secure", c.Secure()),
		zap.String("protocol", c.Protocol()),
	)

	return c.Next()
}
