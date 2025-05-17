package server

import (
	"github.com/stevezaluk/credstack-lib/options"
	"go.uber.org/zap"
)

/*
Log - An abstraction for the Logger. Handles any logic for creating and writing log files here
*/
type Log struct {
	// options - Defines the options that should be used with the logger
	options *options.LogOptions

	// log - A production ready zap.Logger that is initialized when calling NewLog
	log *zap.Logger
}

/*
LogTokenEvent - Handler for logging any kind of token events. This includes generation, revocation, introspection,
and validation.
*/
func (log *Log) LogTokenEvent(eventType string, email string, tokenType string, appId string, apiId string) {
	log.log.Info(
		"TokenEvent",
		zap.String("eventType", eventType),
		zap.String("email", email),
		zap.String("tokenType", tokenType),
		zap.String("appId", appId),
		zap.String("apiId", apiId),
	)
}

/*
LogAuthEvent - Handler for logging any kind of authentication events. This includes login's, logouts, and registration
primarily. Token events are logged using the Log.LogTokenEvent Handler.
*/
func (log *Log) LogAuthEvent(eventType string, email string, username string, method string, appId string) {
	log.log.Info(
		"AuthenticationEvent",
		zap.String("type", eventType),
		zap.String("email", email),
		zap.String("username", username),
		zap.String("auth_method", method),
		zap.String("application_id", appId),
	)
}

/*
LogDatabaseEvent - Logs database specific events, mostly connection and disconnections. Additionally, authentication
errors get logged here as well.
*/
func (log *Log) LogDatabaseEvent(eventType string, hostname string, port int) {
	log.log.Info(
		"DatabaseEvent",
		zap.String("eventType", eventType),
		zap.String("hostname", hostname),
		zap.Int("port", port),
	)
}

/*
LogErrorEvent - Handler for logging any kind of error events.
*/
func (log *Log) LogErrorEvent(description string, err error) {
	log.log.Error(
		"ErrorEvent",
		zap.String("description", description),
		zap.NamedError("error", err),
	)
}

/*
NewLog - Constructs a new Log using the values passed in its parameters. If an options structure is not passed in this
functions parameter, then the Log is initialized with default values. Additionally, if more than 1 are passed here,
only the first is used.
*/
func NewLog(opts ...*options.LogOptions) (*Log, error) {
	if len(opts) == 0 {
		opts = append(opts, new(options.LogOptions))
	}

	/*
		We always initialize a new production ready logger, to ensure that we can log messages in the most
		performant way. Subsequently, no getter for the Log.log variable is provided as the caller should
		never have to interact with this. Use the pre-defined methods for logging messages instead
	*/
	log, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}

	// initialize file logging if it is set in options

	return &Log{
		options: opts[0],
		log:     log,
	}, nil
}
