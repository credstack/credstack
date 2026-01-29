package server

import "github.com/credstack/credstack/sdk/pkg/options"

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
Start - Initializes the server. Connects to the database and initializes the logger
*/
func (server *Server) Start() error {
	server.Log().LogDatabaseEvent("DatabaseConnect",
		server.Database().Options().Hostname,
		int(server.Database().Options().Port),
	)

	/*
		We still need to connect to our database as the constructors for Server do not
		provide this functionality by default.
	*/
	err := server.Database().Connect()
	if err != nil {
		server.Log().LogErrorEvent("Failed to connect to database", err)
		return err
	}

	return nil
}

/*
Stop - Stops the server from running. Disconnects the database and flushes the logger to disk
*/
func (server *Server) Stop() error {
	server.Log().LogDatabaseEvent("DatabaseDisconnect",
		server.Database().Options().Hostname,
		int(server.Database().Options().Port),
	)
	/*
		Then we close our connection to the database gracefully.
	*/
	err := server.Database().Disconnect()
	if err != nil {
		return err // log here
	}

	server.Log().LogShutdownEvent("LogFlush", "Flushing queued logs and closing log file")

	/*
		Then we flush any buffered logs to sync and close the open log file, any errors
		returned from this action will be logged properly
	*/
	err = server.Log().CloseLog()
	if err != nil {
		if err.Error() == "sync /dev/stdout: invalid argument" { // we explicitly ignore this error as it /dev/stdout is not a real file that supports the Sync system call
			return nil
		}
		return err
	}

	return nil
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
