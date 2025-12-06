package options

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
)

type ApiOptions struct {
	// Port - The port number that the API should listen for requests on
	Port int

	// Debug - Enables debug logging for the API. Useful for development
	Debug bool

	// Prefork - Allows the API to run on multiple processes to increase performance
	Prefork bool

	// SkipPreflight - If set to true, then preflight checks are not conducted on API start
	SkipPreflight bool

	// Will eventually support TLS options
}

/*
Api - Returns an ApiOptions structure with some sensible defaults
*/
func Api() *ApiOptions {
	return &ApiOptions{
		Port:    8080,
		Debug:   false,
		Prefork: false, // TODO: set this to true when logging is updated to store PID
	}
}

/*
FromConfig - Fills in all fields present in the ApiOptions structure with configuration values passed
from viper
*/
func (opts *ApiOptions) FromConfig() *ApiOptions {
	return &ApiOptions{
		Port:    viper.GetInt("api.port"),
		Debug:   viper.GetBool("api.debug"),
		Prefork: viper.GetBool("api.prefork"),
	}
}

/*
SetPort - Defines the port number that the API should listen for requests on
*/
func (opts *ApiOptions) SetPort(port int) *ApiOptions {
	opts.Port = port

	return opts
}

/*
SetDebug - If set to true, debug logging will be enabled and the following Fiber options are configured:

EnablePrintRoutes -> True
CaseSensitive -> False
StrictRouting -> False
IdleTimeout -> 10 mins
TrustProxy -> False
EnablePrefork -> False
*/
func (opts *ApiOptions) SetDebug(value bool) *ApiOptions {
	opts.Debug = value

	return opts
}

/*
SetPrefork - If set to true, then API will be run against multiple processes. Use this in production, performance
sensitive environments. If Debug is set to true, then this value is ignored.
*/
func (opts *ApiOptions) SetPrefork(value bool) *ApiOptions {
	opts.Prefork = value

	return opts
}

/*
SetSkipPreflight - If set to true, then preflight checks are skipped on API execution
*/
func (opts *ApiOptions) SetSkipPreflight(value bool) *ApiOptions {
	opts.SkipPreflight = value

	return opts
}

/*
FiberConfig - Returns a fiber.Config  structure for the Api structure to consume
*/
func (opts *ApiOptions) FiberConfig() fiber.Config {
	config := fiber.Config{
		CaseSensitive:    true,
		StrictRouting:    true,
		DisableKeepalive: true,
	}

	if opts.Debug {
		config.CaseSensitive = false
		config.StrictRouting = false
		config.IdleTimeout = 10 * time.Minute
		config.TrustProxy = true
	}

	return config
}

/*
ListenerConfig - Returns a fiber.ListenConfig structure for the Api structure to consume
*/
func (opts *ApiOptions) ListenerConfig() fiber.ListenConfig {
	listenConfig := fiber.ListenConfig{
		DisableStartupMessage: true,
		EnablePrefork:         opts.Prefork,
		ListenerNetwork:       fiber.NetworkTCP4,
	}

	if opts.Debug {
		listenConfig.EnablePrefork = false
		listenConfig.EnablePrintRoutes = true
	}

	return listenConfig
}
