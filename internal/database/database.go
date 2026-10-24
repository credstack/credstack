package database

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/mongo"
	mongoOpts "go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// Database Core abstraction around the lifecycle of database connections. Makes no assumptions around how data is returned from the database
type Database struct {
	// config The database config
	config Config

	// client A pointer to the underlying Mongo client
	client *mongo.Client

	// database A pointer to the underlying Mongo database
	database *mongo.Database
}

// Collection Returns the mongo collection of the given name
func (database *Database) Collection(collection string) *mongo.Collection {
	return database.database.Collection(collection)
}

// Connect Initiates a connection to the mongo server described in Config. After a connection is established, the connection is tested
// for availability with database.client.Ping()
func (database *Database) Connect() error {
	client, err := mongo.Connect(database.config.Mongo())
	if err != nil {
		return err
	}

	// TODO: readperf.Nearest can break some assumptions around clustering
	err = client.Ping(context.Background(), readpref.Nearest())
	if err != nil {
		return err
	}

	database.client = client
	database.database = client.Database(database.config.DefaultDatabase)

	return nil
}

// Disconnect gracefully disconnect from the mongo database
func (database *Database) Disconnect() error {
	err := database.client.Disconnect(context.Background())
	if err != nil {
		return err
	}

	return nil
}

// PreFlight Ensures that required collections and indexes exist in the default database described in Config. Returns
// a map representing any errors that occured during preflight
func (database *Database) PreFlight() map[string]error {
	indexingMap := database.config.IndexingMap()
	failed := make(map[string]error, len(indexingMap))

	// TODO: This can be optimized to make less calls
	for collection, fields := range indexingMap {
		err := database.database.CreateCollection(
			context.Background(),
			collection,
		)

		if err != nil {
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
			failed[collection] = err
			continue
		}
	}

	return failed
}

// New Initializes a new Database and returns a pointer to it. Does not connect to the database automatically
func New(config Config) *Database {
	return &Database{
		config: config,
	}
}
