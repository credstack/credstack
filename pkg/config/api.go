package config

import (
	"fmt"
	"net/netip"
)

// Config Represents common API Configuration options exposed to a maintainer
type ApiConfig struct {
	// Port The port the API should listen for requests on
	Port int `json:"port" yaml:"port" mapstructure:"port"`

	// Debug If set to true, set gin.ReleaseMode to debug and inject pprof routes
	Debug bool `json:"debug" yaml:"debug" mapstructure:"debug"`

	// UseTLS If set to true, enforce TLS on the API Server
	UseTLS bool `json:"use_tls" yaml:"useTls" mapstructure:"use_tls"`

	// TLSCert A unix path to a TLS certificate. Must be PEM encoded
	TLSCert string `json:"tls_cert" yaml:"tlsCert" mapstructure:"tlsCert"`

	// TLSKey A unix path to a TLS Key. Must be PEM encoded
	TLSKey string `json:"tls_key" yaml:"tlsKey" mapstructure:"tlsKey"`

	// TrustedIPs A list of IP addresses representing your proxy servers that should be added
	// to Gin's trusted IP list. IP addresses defined here force Gin to respect the X-Forwarded-For
	// header
	TrustedIPs []string `json:"trusted_ips" yaml:"trustedIps" mapstructure:"trusted_ips"`

	// TrustedPlatform An HTTP Header that represent how a real client IP address is being forwarded
	// to the API. Each platform can use a different Header for this, so if yours uses a custom one, provide it here
	TrustedPlatform string `json:"trusted_platform" yaml:"trustedPlatform" mapstructure:"trusted_platform"`
}

// Validate Validates the config file for correctness
func (config ApiConfig) Validate() error {
	if config.UseTLS {
		if config.TLSCert == "" || config.TLSKey == "" {
			return fmt.Errorf("api config validation err: config.TLSCert and config.TLSKey cannot be empty")
		}
	}

	for _, ip := range config.TrustedIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			return fmt.Errorf("api config validation err: %s is not a valid IP address", ip)
		}
	}

	return nil
}

// Addr Returns an address string for use with lower level HTTP libraries
func (config ApiConfig) Addr() string {
	return fmt.Sprintf(":%d", config.Port)
}

// DefaultConfig Initializes a new api.Config and returns a pointer to it
func DefaultApiConfig() ApiConfig {
	return ApiConfig{
		Debug:           true,
		Port:            8080,
		TrustedIPs:      nil,
		TrustedPlatform: "",
	}
}
