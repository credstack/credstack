package server

import "github.com/credstack/credstack/pkg/options"

/*
Server - Provides an abstraction of any commonly used resources that services would need
to interact with. Also provides lifecycle control for these objects
*/
type Server struct {
	// database - Provides a connected database for services to interact with
	database *Database

	// log - Provides a production-ready Zap logger for services to interact with
	log *Log
}

/*
Database - Returns a pointer to the Database that the server is currently using. The same
database gets re-used across multiple services as re-connecting to the database across every
function call gets expensive
*/
func (server *Server) Database() *Database {
	return server.database
}

/*
Log - Returns a pointer to the Log that the server is currently using. If you are using this
be sure to call Log.Close once the application exists as existing writes that have been buffered
will get flushed
*/
func (server *Server) Log() *Log {
	return server.log
}

/*
New - Constructs a new server using configurations passed in the arguments of this function
*/
func New(dbOpts *options.DatabaseOptions, logOpts *options.LogOptions) *Server {
	return &Server{
		database: NewDatabase(dbOpts),
		log:      NewLog(logOpts),
	}
}

/*
Default - Initializes the server and its components with default configurations
*/
func Default() *Server {
	/*
		We don't need to pass any options here, as these constructors will
		automatically fill them with defaults
	*/
	return &Server{
		database: NewDatabase(),
		log:      NewLog(),
	}
}

/*
FromConfig - Initializes the server and its components with configurations created from viper values
*/
func FromConfig() *Server {
	return &Server{
		database: NewDatabase(options.Database().FromConfig()),
		log:      NewLog(options.Log().FromConfig()),
	}
}
