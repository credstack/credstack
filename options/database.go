package options

import (
	"github.com/spf13/viper"
	"time"
)

type DatabaseOptions struct {
	// Hostname - Defines the hostname that the MongoDB server can be accessed at
	Hostname string

	// Port - Defines the port number that the MongoDB server is listening for connections on
	Port uint32

	// DefaultDatabase - Defines the default database that should be used for storing collections
	DefaultDatabase string

	// UseAuthentication - If set to false, then any other auth related configs wont be evaluated
	UseAuthentication bool

	// AuthenticationDatabase - Defines the database that should be used for authentication
	AuthenticationDatabase string

	// Username - Defines the username that should be used for authentication with MongoDB
	Username string

	// Password - Defines the password that should be used for authentication with MongoDB
	Password string

	// ConnectionTimeout - The duration that credstack should wait for before force closing a Mongo connection
	ConnectionTimeout time.Duration
}

/*
Database - Returns a DatabaseOptions structure with some sensible defaults. Authentication is not enabled here
by default as MongoDB does not have default authentication. Despite this not being enabled, the AuthenticationDatabase
is set to admin by default as this tends to be common when working with MongoDB (although not recommended)
*/
func Database() *DatabaseOptions {
	return &DatabaseOptions{
		Hostname:               "127.0.0.1",
		Port:                   27017,
		DefaultDatabase:        "credstack",
		UseAuthentication:      false,
		AuthenticationDatabase: "admin",
		ConnectionTimeout:      15 * time.Second,
	}
}

/*
FromConfig - Fills in all fields present in the DatabaseOptions structure with the values from
viper. Any previously present configuration values will be overwritten with this call
*/
func (database *DatabaseOptions) FromConfig() *DatabaseOptions {
	return &DatabaseOptions{
		Hostname:               viper.GetString("mongo.hostname"),
		Port:                   uint32(viper.GetInt("mongo.port")),
		DefaultDatabase:        viper.GetString("mongo.default_database"),
		UseAuthentication:      viper.GetBool("mongo.use_authentication"),
		AuthenticationDatabase: viper.GetString("mongo.authentication_database"),
		Username:               viper.GetString("mongo.username"),
		Password:               viper.GetString("mongo.password"),
		ConnectionTimeout:      viper.GetDuration("mongo.connection_timeout"),
	}
}
