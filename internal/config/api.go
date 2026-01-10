package config

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
