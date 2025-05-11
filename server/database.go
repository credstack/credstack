package server

import (
	"fmt"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"time"
)

type Database struct {
	// options - A structure storing client related options relating to authentication
	options *options.ClientOptions

	// defaultDatabase - The default database that Mongo should use
	defaultDatabase string

	// client - A reference to the Mongo client that is used to perform operations
	client *mongo.Client

	// database - A reference to the Mongo database storing data the server needs to access
	database *mongo.Database
}

/*
NewDatabase - Instantiates a new database object. Does not connect automatically, this needs to be done
with Database.Connect. The default timeout for database connections is 15 seconds
*/
func NewDatabase(hostname string, port int, database string) *Database {
	opts := options.Client().
		SetHosts([]string{fmt.Sprintf("%s:%d", hostname, port)}).
		SetDirect(true).
		SetTimeout(15 * time.Second)

	return &Database{
		options:         opts,
		defaultDatabase: database,
	}
}

/*
Client - A getter for returning the underlying mongo.Client pointer
*/
func (database *Database) Client() *mongo.Client {
	return database.client
}

/*
Database - A getter for returning the underlying mongo.Database pointer
*/
func (database *Database) Database() *mongo.Database {
	return database.database
}

/*
SetSCRAMAuthentication - Instructs the mongo.Client to use SCRAM authentication when establishing
a connection to the MongoDB database. SCRAM-SHA-256 is used as the default authentication mechanism
here as it balances security with performance while establishing connections.

The default authentication source is set to the value passed in Database.defaultDatabase. Generally
using 'admin' as the default authentication source is not recommended as users should be isolated
only to the database that they need access to. This client expects read/write permissions to the default
database collections that are created with the Database.Init method.
*/
func (database *Database) SetSCRAMAuthentication(username string, password string) {
	credential := options.Credential{
		AuthMechanism: "SCRAM-SHA-256",
		AuthSource:    database.defaultDatabase,
		Username:      username,
		Password:      password,
	}

	database.options.SetAuth(credential)
}

/*
Connect - General wrapper around mongo.Connect. Generally, the mongo session created with
this function should be re-used across multiple calls to ensure that excess resources
are not wasted initiating additional connections to MongoDB.
*/
func (database *Database) Connect() error {
	client, err := mongo.Connect(database.options)
	if err != nil {
		return err
	}

	database.client = client
	database.database = client.Database(database.defaultDatabase)

	return nil
}
