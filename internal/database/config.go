package database

import (
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Config struct {
	// Hostname Defines the hostname that the MongoDB server can be accessed at
	Hostname string `json:"hostname" yaml:"hostname" mapstructure:"hostname"`

	// Port Defines the port number that the MongoDB server is listening for connections on
	Port uint32 `json:"port" yaml:"port" mapstructure:"port"`

	// DefaultDatabase Defines the default database that should be used for storing collections
	DefaultDatabase string `json:"default_database" yaml:"default_database" mapstructure:"default_database"`

	// UseAuthentication If set to false, then any other auth related configs wont be evaluated
	UseAuthentication bool `json:"use_authentication" yaml:"use_authentication" mapstructure:"use_authentication"`

	// AuthenticationDatabase Defines the database that should be used for authentication
	AuthenticationDatabase string `json:"authentication_database" yaml:"authentication_database" mapstructure:"authentication_database"`

	// Username Defines the username that should be used for authentication with MongoDB
	Username string `json:"username" yaml:"username" mapstructure:"username"`

	// Password Defines the password that should be used for authentication with MongoDB
	Password string `json:"password" yaml:"password" mapstructure:"password"`

	// ConnectionTimeout The duration that credstack should wait for before force closing a Mongo connection
	ConnectionTimeout time.Duration `json:"connection_timeout" yaml:"connection_timeout" mapstructure:"connection_timeout"`
}

// Collections Returns the default collections that credstack expects to be able to read/write to. This
// is primarily used with Database.Init. This really shouldn't be changed so there is no setter defined for these
func (config *Config) Collections() []string {
	return []string{
		"user",
		"role",
		"scope",
		"client",
		"resource_server",
		"key",
		"jwk",
	}
}

// IndexingMap Returns the map used for creating indexes on the credstack's default collections. All the
// indexes listed here are created as unique indexes. This really shouldn't be changed so there is no setter
// defined for these
func (config *Config) IndexingMap() map[string]bson.D {
	return map[string]bson.D{
		"user":            {{Key: "email", Value: 1}, {Key: "header.identifier", Value: 1}},
		"role":            {{Key: "header.identifier", Value: 1}},
		"scope":           {{Key: "header.identifier", Value: 1}},
		"client":          {{Key: "client_id", Value: 1}, {Key: "header.identifier", Value: 1}},
		"resource_server": {{Key: "header.identifier", Value: 1}},
		"key":             {{Key: "header.identifier", Value: 1}},
		"jwk":             {{Key: "kid", Value: 1}},
	}
}

// Mongo Converts any pre-defined options declared in DatabaseConfig to an
// options.ClientOptions struct so that this can be used cleanly with the Database
// structure
func (config *Config) Mongo() *options.ClientOptions {
	// TODO:  SetDirect breaks clustering
	clientOptions := options.Client().
		SetHosts([]string{fmt.Sprintf("%s:%d", config.Hostname, config.Port)}).
		SetDirect(true).
		SetTimeout(config.ConnectionTimeout)

	// TODO: Only supporting SCRAM-SHA-256 here
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

// DefaultConfig Initializes the DatabaseConfig structure with sane defaults
func DefaultConfig() Config {
	return Config{
		Hostname:               "127.0.0.1",
		Port:                   27017,
		ConnectionTimeout:      15 * time.Second,
		UseAuthentication:      true,
		DefaultDatabase:        "credstack",
		AuthenticationDatabase: "admin",
		Username:               "admin",
		Password:               "admin",
	}
}
