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
