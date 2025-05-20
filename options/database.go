package options

import (
	"fmt"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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
func (opts *DatabaseOptions) FromConfig() *DatabaseOptions {
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

/*
ToMongoOptions - Converts any pre-defined options declared in DatabaseOptions to an
options.ClientOptions struct so that this can be used cleanly with the Database
structure
*/
func (opts *DatabaseOptions) ToMongoOptions() *options.ClientOptions {
	/*
		So realistically, SetDirect should probably be set to false here and
		the DatabaseOptions structure should be modified so that multiple hosts
		in a cluster can be used. I really don't think many people are going to
		use this functionality to begin with so we will cross that bridge when
		we come to it.
	*/
	clientOptions := options.Client().
		SetHosts([]string{fmt.Sprintf("%s:%d", opts.Hostname, opts.Port)}).
		SetDirect(true).
		SetTimeout(opts.ConnectionTimeout)

	/*
		Only SCRAM-SHA-256 is going to be set here as it provides a nice balance between
		performance and security. This value isn't externalized either to the broader
		DatabaseOptions structure so this shouldn't need to change
	*/
	const AuthMechanism = "SCRAM-SHA-256"

	if opts.UseAuthentication {
		clientOptions.SetAuth(options.Credential{
			AuthMechanism: AuthMechanism,
			AuthSource:    opts.AuthenticationDatabase,
			Username:      opts.Username,
			Password:      opts.Password,
		})
	}

	return clientOptions
}

/*
SetHostname - Defines the hostname of the MongoDB database that you want to connect to. You do not need
to prepend this with the mongo:// protocol identifier, this should just be the FQDN of the MongoDB instance
*/
func (opts *DatabaseOptions) SetHostname(hostname string) *DatabaseOptions {
	opts.Hostname = hostname

	return opts
}

/*
SetPort - Sets the port that your MongoDB server is listening for connections on. If this value is set lower
than 0, then a default of 27017 is used instead.
*/
func (opts *DatabaseOptions) SetPort(port int) *DatabaseOptions {
	if port < 0 {
		port = 27017
	}

	opts.Port = uint32(port)

	return opts
}

/*
SetDefaultDatabase - Set's the default database that cred-stack will assume that its collections will live.
If server.Database.Init is called with this set, then collections (and indexes) will be initialized here.
*/
func (opts *DatabaseOptions) SetDefaultDatabase(value string) *DatabaseOptions {
	opts.DefaultDatabase = value

	return opts
}

/*
SetUseAuthentication - If set to true, then the authentication values provided at DatabaseOptions.Username,
DatabaseOptions.Password, and DatabaseOptions.AuthenticationDatabase are evaluated and authentication is
attempted on the MongoDB server
*/
func (opts *DatabaseOptions) SetUseAuthentication(value bool) *DatabaseOptions {
	opts.UseAuthentication = value

	return opts
}

/*
SetAuthenticationDatabase - Defines the default database that the MongoDB server will look for users and roles
within. When calling DatabaseOptions.Database, this is set to 'admin'. Ideally this should be set to the default
database defined at DatabaseOptions.DefaultDatabase. Users should be seperated to only the databases that they
need access to, and should be treated more or less as ephemeral
*/
func (opts *DatabaseOptions) SetAuthenticationDatabase(value string) *DatabaseOptions {
	opts.AuthenticationDatabase = value

	return opts
}

/*
SetUsername - Defines the username of the MongoDB user that the MongoDB client should use when performing
authentication
*/
func (opts *DatabaseOptions) SetUsername(value string) *DatabaseOptions {
	opts.Username = value

	return opts
}

/*
SetPassword - Defines the clear text password of the MongoDB user that the MongoDB client should use when performing
authentication
*/
func (opts *DatabaseOptions) SetPassword(value string) *DatabaseOptions {
	opts.Password = value

	return opts
}

/*
SetConnectionTimeout - Defines the default for amount of time that the MongoDB client should use when attempting
to connect to a server. If a value less than 0 is provided, then seconds is set to 15
*/
func (opts *DatabaseOptions) SetConnectionTimeout(seconds int) *DatabaseOptions {
	if seconds < 0 {
		seconds = 15
	}

	opts.ConnectionTimeout = time.Duration(seconds) * time.Second

	return opts
}

/*
DefaultCollections - Returns the default collections that credstack expects to be able to read/write to. This
is primarily used with Database.Init. This really shouldn't be changed so there is no setter defined for these
*/
func (opts *DatabaseOptions) DefaultCollections() []string {
	return []string{
		"user",
		"role",
		"scope",
		"api",
		"application",
		"token",
	}
}

/*
IndexingMap - Returns the map used for creating indexes on the credstack's default collections. All the
indexes listed here are created as unique indexes. This really shouldn't be changed so there is no setter
defined for these
*/
func (opts *DatabaseOptions) IndexingMap() map[string]bson.D {
	return map[string]bson.D{
		"user":        {{Key: "email", Value: 1}, {Key: "header.identifier", Value: 1}},
		"role":        {{Key: "header.identifier", Value: 1}},
		"scope":       {{Key: "header.identifier", Value: 1}},
		"application": {{Key: "client_id", Value: 1}, {Key: "header.identifier", Value: 1}},
		"api":         {{Key: "header.identifier", Value: 1}},
		"token":       {{Key: "token", Value: 1}, {Key: "header.identifier", Value: 1}},
	}
}
