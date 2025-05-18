package server

import (
	"context"
	"github.com/stevezaluk/credstack-lib/options"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongoOpts "go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

/*
Database - Defines the core abstraction around a MongoDB database. This structure provides construction from
Viper config values, along with basic parameters. Additionally, authentication can be controlled here without
needing to be aware of MongoDB's underlying API structure.

Queries that would be made on collections (like findOne) are not abstracted here as I didn't want to overcomplicate
this abstraction. I find that having service level packages (like the Token service) directly interact with the raw
mongo.Collection pointer vastly simplifies maintenance as I don't need to re-abstract whatever functionality that
MongoDB is providing to me

If a service wishes to make Database calls, it can call the Database.Collection method and pass the collection that
it wants to use in the parameter.
*/
type Database struct {
	// options - A structure storing client related options relating to authentication
	options *options.DatabaseOptions

	// defaultDatabase - The default database that Mongo should use
	defaultDatabase string

	// client - A reference to the Mongo client that is used to perform operations
	client *mongo.Client

	// database - A reference to the Mongo database storing data the server needs to access
	database *mongo.Database
}

/*
Options - Returns a pointer to the options struct used with the Database
*/
func (database *Database) Options() *options.DatabaseOptions {
	return database.options
}

/*
Collection - A getter for returning the underlying mongo.Collection pointer
*/
func (database *Database) Collection(collection string) *mongo.Collection {
	return database.database.Collection(collection)
}

/*
Connect - General wrapper around mongo.Connect. Generally, the mongo session created with
this function should be re-used across multiple calls to ensure that excess resources
are not wasted initiating additional connections to MongoDB.
*/
func (database *Database) Connect() error {
	client, err := mongo.Connect(database.options.ToMongoOptions())
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
Disconnect - Gracefully disconnects from the MongoDB client. Acts as a wrapper
around mongo.Client.Disconnect and returns any errors that arise from it
*/
func (database *Database) Disconnect() error {
	err := database.client.Disconnect(context.Background())
	if err != nil {
		return err
	}

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
*/
func (database *Database) Init() map[string]error {
	/*
		indexingMap - Here we are defining a map representing the collections
		that need to be created, along with any indexes that need to be created
		on said collections.

		All the ones listed here are getting added as unique indexes, to protect against
		duplicated data
	*/
	indexingMap := database.options.IndexingMap()

	// failed - What is returned at the end of this functions execution
	failed := make(map[string]error, len(indexingMap))

	/*
		Generally, this can be optimized to consume even less DB calls with the CreateMultiple function, however this
		function is only really called once through the entire lifetime of the database
	*/
	for collection, fields := range indexingMap {
		err := database.database.CreateCollection(
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
			Options: mongoOpts.Index().SetUnique(true),
		}

		_, err = database.
			database.
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

/*
NewDatabase - Constructs a new Database using the values passed in each of its parameters. Calling this function does
not connect to the database automatically. This needs to be done post-construction with Database.Connect. If an options
structure is not passed in this functions parameter, then the Database is initialized with default values. Additionally,
if more than 1 are passed here, only the first is used.

If you need to construct a new database from viper configurations, you should use options.DatabaseOptions.FromConfig
*/
func NewDatabase(opts ...*options.DatabaseOptions) *Database {
	if len(opts) == 0 {
		opts = append(opts, options.Database())
	}

	return &Database{
		options: opts[0],
	}
}
