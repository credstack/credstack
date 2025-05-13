package options

type DatabaseOptions struct {
	// Hostname - Defines the hostname that the MongoDB server can be accessed at
	Hostname string

	// Port - Defines the port number that the MongoDB server is listening for connections on
	Port uint32

	// DefaultDatabase - Defines the default database that should be used for storing collections
	DefaultDatabase string

	// UseAuthentication - If set to false, then any other auth related configs wont be evaluated
	UseAuthentication bool

	// Username - Defines the username that should be used for authentication with MongoDB
	Username string

	// Password - Defines the password that should be used for authentication with MongoDB
	Password string

	// AuthenticationDatabase - Defines the database that should be used for authentication
	AuthenticationDatabase string
}

/*
Database - Returns a DatabaseOptions structure with some sensible defaults
*/
func Database() *DatabaseOptions {
	return &DatabaseOptions{
		Hostname:          "127.0.0.1",
		Port:              27017,
		DefaultDatabase:   "credstack",
		UseAuthentication: false,
	}
}
