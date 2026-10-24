package server

import (
	"fmt"
	"log/slog"
	"runtime"

	"github.com/credstack/credstack/internal/database"
	"github.com/credstack/credstack/internal/log"
	"github.com/credstack/credstack/internal/version"
	"github.com/credstack/credstack/pkg/config"
)

/*
Server - Provides an abstraction of any commonly used resources that services would need
to interact with. Also provides lifecycle control for these objects
*/
type Server struct {
	// Config The global configuration structure used for the entire application
	Config *config.ServerConfig

	// database - Provides a connected database for services to interact with
	database *database.Database
}

/*
Database - Returns a pointer to the Database that the server is currently using. The same
database gets re-used across multiple services as re-connecting to the database across every
function call gets expensive
*/
func (server *Server) Database() *database.Database {
	return server.database
}

/*
Start - Initializes the server. Connects to the database and initializes the logger
*/
func (server *Server) Start() error {
	if err := log.Init(server.Config.LogConfig); err != nil {
		return fmt.Errorf("log: Failed to initialize logger: %v", err)
	}

	slog.Info("version", "sem_ver", version.SemVer, "commit_sha", version.CommitSHA, "build_date", version.BuildDate, "runtime", runtime.Version())
	slog.Info("connecting to database", "hostname", server.Config.DatabaseConfig.Hostname, "port", server.Config.DatabaseConfig.Port)

	err := server.Database().Connect()
	if err != nil {
		return err
	}

	return nil
}

/*
Stop - Stops the server from running. Disconnects the database and flushes the logger to disk
*/
func (server *Server) Stop() error {
	slog.Info("disconncting from database", "hostname", server.Config.DatabaseConfig.Hostname, "port", server.Config.DatabaseConfig.Port)

	/*
		Then we close our connection to the database gracefully.
	*/
	err := server.Database().Disconnect()
	if err != nil {
		return err // log here
	}

	return nil
}

// New Initializes a new Server structure with the values provided in the Config structure
func New(config *config.ServerConfig) *Server {
	return &Server{
		Config:   config,
		database: database.New(config.DatabaseConfig),
	}
}
