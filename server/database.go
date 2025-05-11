package server

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
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
Collection - A getter for returning the underlying mongo.Collection pointer
*/
func (database *Database) Collection(collection string) *mongo.Collection {
	return database.database.Collection(collection)
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

	/*
		Ideally we want to consume as little calls as possible, however mongo.Client.Ping is
		generally a fairly cheap call. Additionally, authentication errors do not get passed
		from the error returned with mongo.Connect, only from mongo.Ping

		Read preferences is set to nearest here, as opposed to primary as we really just want
		to validate that we were able to connect to the database successfully
	*/
	err = client.Ping(context.Background(), readpref.Nearest())
	if err != nil {
		return err
	}

	database.client = client
	database.database = client.Database(database.defaultDatabase)

	return nil
}

/*
Init - Initializes MongoDB with default collections and indexes where they are needed. The Init function anticipates
that the default database already exists and that authentication has been established on it. Automation for this
is not provided.

Each collection applies a unique index on header.identifier to ensure that objects with duplicated UUID's do not
get inserted. This really shouldn't happen any way as these are generated based on unique values for its respective
object, applying indexes here provides an easier way to determine if an object already exists without consuming
an additional database call.

A map is returned representing the errors that were encountered during the initialization process. The maps key
represents the name of the collection and the value is the error that occurred. If an error occurs during initialization
then the current iteration of the loop is continued and initialization is continued

Generally, this can be optimized to consume even less DB calls with the CreateMultiple function, however this
function is only really called once through the entire lifetime of the database
*/
func (database *Database) Init() map[string]error {
	// indexingMap - Defines a map for how to create (general) indexes on each collection
	indexingMap := map[string]bson.D{
		"user":         bson.D{{Key: "email", Value: 1}, {Key: "header.identifier", Value: 1}},
		"role":         bson.D{{Key: "header.identifier", Value: 1}},
		"scope":        bson.D{{Key: "header.scope", Value: 1}},
		"application":  bson.D{{Key: "client_id", Value: 1}, {Key: "header.identifier", Value: 1}},
		"api":          bson.D{{Key: "header.identifier", Value: 1}},
		"access_token": bson.D{{Key: "token", Value: 1}, {Key: "header.identifier", Value: 1}},
	}

	// failed - What is returned at the end of this functions execution
	failed := make(map[string]error, len(indexingMap))

	for collection, fields := range indexingMap {
		err := database.Database().CreateCollection(
			context.Background(),
			collection,
		)

		if err != nil {
			// perform some logging here
			failed[collection] = err
			continue // we continue here as if we cant create the collection, we cant create the indexes
		}

		index := mongo.IndexModel{
			Keys:    fields,
			Options: options.Index().SetUnique(true),
		}

		_, err = database.
			Database().
			Collection(collection).
			Indexes().
			CreateOne(context.Background(), index)

		if err != nil {
			// perform some logging here
			failed[collection] = err
			continue
		}
	}

	return failed
}
