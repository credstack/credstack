package config

import "time"

type DatabaseConfig struct {
	// Hostname - Defines the hostname that the MongoDB server can be accessed at
	Hostname string `mapstructure:"hostname"`

	// Port - Defines the port number that the MongoDB server is listening for connections on
	Port uint32 `mapstructure:"port"`

	// DefaultDatabase - Defines the default database that should be used for storing collections
	DefaultDatabase string `mapstructure:"default_database"`

	// UseAuthentication - If set to false, then any other auth related configs wont be evaluated
	UseAuthentication bool `mapstructure:"use_authentication"`

	// AuthenticationDatabase - Defines the database that should be used for authentication
	AuthenticationDatabase string `mapstructure:"authentication_database"`

	// Username - Defines the username that should be used for authentication with MongoDB
	Username string `mapstructure:"username"`

	// Password - Defines the password that should be used for authentication with MongoDB
	Password string `mapstructure:"password"`

	// ConnectionTimeout - The duration that credstack should wait for before force closing a Mongo connection
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`
}
