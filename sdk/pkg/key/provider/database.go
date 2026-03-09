package provider

import "github.com/credstack/credstack/sdk/pkg/server"

// DatabaseKeyProvider Represents the default key provider. Any and all key operations are stored directly within
// MongoDB. The DatabaseKeyProvider provides little to no security directly and relies on security measures that
// are implemented at the database level
type DatabaseKeyProvider struct {
	database *server.Database
}

// NewDatabaseKeyProvider Initializes a new database key provider
func NewDatabaseKeyProvider(database *server.Database) *DatabaseKeyProvider {
	return &DatabaseKeyProvider{
		database: database,
	}
}
