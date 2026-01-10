package config

import (
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

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

/*
DefaultCollections - Returns the default collections that credstack expects to be able to read/write to. This
is primarily used with Database.Init. This really shouldn't be changed so there is no setter defined for these
*/
func (config *DatabaseConfig) DefaultCollections() []string {
	return []string{
		"user",
		"role",
		"scope",
		"client",
		"resource_server",
		"token",
		"key",
		"jwk",
	}
}

/*
IndexingMap - Returns the map used for creating indexes on the credstack's default collections. All the
indexes listed here are created as unique indexes. This really shouldn't be changed so there is no setter
defined for these
*/
func (config *DatabaseConfig) IndexingMap() map[string]bson.D {
	return map[string]bson.D{
		"user":            {{Key: "email", Value: 1}, {Key: "header.identifier", Value: 1}},
		"role":            {{Key: "header.identifier", Value: 1}},
		"scope":           {{Key: "header.identifier", Value: 1}},
		"client":          {{Key: "client_id", Value: 1}, {Key: "header.identifier", Value: 1}},
		"resource_server": {{Key: "header.identifier", Value: 1}},
		"token":           {{Key: "token", Value: 1}},
		"key":             {{Key: "header.identifier", Value: 1}},
		"jwk":             {{Key: "kid", Value: 1}},
	}
}

/*
ToMongoOptions - Converts any pre-defined options declared in DatabaseConfig to an
options.ClientOptions struct so that this can be used cleanly with the Database
structure
*/
func (config *DatabaseConfig) ToMongoOptions() *options.ClientOptions {
	/*
		So realistically, SetDirect should probably be set to false here and
		the DatabaseConfig structure should be modified so that multiple hosts
		in a cluster can be used. I really don't think many people are going to
		use this functionality to begin with so we will cross that bridge when
		we come to it.
	*/
	clientOptions := options.Client().
		SetHosts([]string{fmt.Sprintf("%s:%d", config.Hostname, config.Port)}).
		SetDirect(true).
		SetTimeout(config.ConnectionTimeout)

	/*
		Only SCRAM-SHA-256 is going to be set here as it provides a nice balance between
		performance and security. This value isn't externalized either to the broader
		DatabaseConfig structure so this shouldn't need to change
	*/
	const AuthMechanism = "SCRAM-SHA-256"

	if config.UseAuthentication {
		clientOptions.SetAuth(options.Credential{
			AuthMechanism: AuthMechanism,
			AuthSource:    config.AuthenticationDatabase,
			Username:      config.Username,
			Password:      config.Password,
		})
	}

	return clientOptions
}
