package config

import (
	"time"

	"github.com/gofiber/fiber/v3"
)

type ApiConfig struct {
	// Port - The port number that the API should listen for requests on
	Port int `mapstructure:"port"`

	// Debug - Enables debug logging for the API. Useful for development
	Debug bool `mapstructure:"debug"`

	// Prefork - Allows the API to run on multiple processes to increase performance
	Prefork bool `mapstructure:"prefork"`

	// SkipPreflight - If set to true, then preflight checks are not conducted on API start
	SkipPreflight bool `mapstructure:"skip_preflight"`
}

/*
FiberConfig - Returns a fiber.Config  structure for the Api structure to consume
*/
func (config *ApiConfig) FiberConfig() fiber.Config {
	fiberConfig := fiber.Config{
		CaseSensitive:    true,
		StrictRouting:    true,
		DisableKeepalive: true,
	}

	if config.Debug {
		fiberConfig.CaseSensitive = false
		fiberConfig.StrictRouting = false
		fiberConfig.IdleTimeout = 10 * time.Minute
		fiberConfig.TrustProxy = true
	}

	return fiberConfig
}

/*
ListenerConfig - Returns a fiber.ListenConfig structure for the Api structure to consume
*/
func (config *ApiConfig) ListenerConfig() fiber.ListenConfig {
	listenConfig := fiber.ListenConfig{
		DisableStartupMessage: true,
		EnablePrefork:         config.Prefork,
		ListenerNetwork:       fiber.NetworkTCP4,
	}

	if config.Debug {
		listenConfig.EnablePrefork = false
		listenConfig.EnablePrintRoutes = true
	}

	return listenConfig
}

// DefaultApiConfig Initializes the ApiConfig structure with sane defaults
func DefaultApiConfig() ApiConfig {
	return ApiConfig{
		Port:          8080,
		Debug:         false,
		Prefork:       false,
		SkipPreflight: false,
	}
}
