package config

type ApiConfig struct {
	// Port - The port number that the API should listen for requests on
	Port int

	// Debug - Enables debug logging for the API. Useful for development
	Debug bool

	// Prefork - Allows the API to run on multiple processes to increase performance
	Prefork bool

	// SkipPreflight - If set to true, then preflight checks are not conducted on API start
	SkipPreflight bool
}
