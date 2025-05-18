package server

import (
	"github.com/stevezaluk/credstack-lib/options"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"time"
)

/*
Log - An abstraction for the Logger. Handles any logic for creating and writing log files here
*/
type Log struct {
	// options - Defines the options that should be used with the logger
	options *options.LogOptions

	// log - A production ready zap.Logger that is initialized when calling NewLog
	log *zap.Logger

	// fp - A pointer to the open file that Zap is using for logging. Stored here so that it can be closed safely
	fp *os.File
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
CloseLog - Sync's buffered log entries to log's core and if the user is using file logging, its associating
file is gracefully closed. This should really be called in the event that a panic happens in underlying code
so if you are utilizing this, then call this using `defer`
*/
func (log *Log) CloseLog() error {
	/*
		Zap always recommends that Sync is called before the application exits. Given that Zap is a buffered
		logging solution, this is required.
	*/
	err := log.log.Sync()
	if err != nil {
		return err
	}

	/*
		Adding a conditional here as we don't want a nil pointer dereference in the event
		that the caller is not using file logging
	*/
	if log.fp != nil {
		err = log.fp.Close()
		if err != nil {
			return err
		}
	}

	return nil
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

	log := &Log{
		options: opts[0],
	}

	/*
		By default, the consoleCore is always initialized, this ensures that we can always provide console
		logging for the application. When options.Log is called, this gets initialized with the default
		production encoder that Zap provides
	*/
	consoleCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(log.options.EncoderConfig),
		zapcore.AddSync(os.Stdout),
		log.options.LogLevel,
	)

	/*
		In zap, by using NewTee we can duplicate logs across multiple cores. In our case we are going to use
		this for both console logging (STDOUT) and through file logging in the form of JSON files. Ideally,
		the user wouldn't even use logging files, and they would just aggregate logs through Loki or a similar
		tool, however I wanted to write the feature anyway to support less complex use cases
	*/
	core := zapcore.NewTee(consoleCore)

	if log.options.UseFileLogging {
		// filename - Provides dead simple log rotation. The timestamp provided here is arbitrary and go uses this
		// as a reference for how to build the format for time.Now
		filename := "/credstack-" + time.Now().Format("20060102T150405") + ".log"

		/*
			os.OpenFile expects this directory to exist, and should be created before utilizing file logging
		*/
		fp, err := os.OpenFile(log.options.LogPath+filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			/*
				This should really change here. If the file logger cannot be initialized a warning log entry
				can be created informing the user that only stdout logging is enabled.
			*/
			return nil, err
		}

		// The pointer to the open file is stored here so that it can be safely closed when Log.Close is called
		log.fp = fp

		/*
			We are utilizing the same EncoderConfig that is provided in the consoleCore, as we really want to keep
			logs consistent across stdout and through files. Additionally, I am trying to avoid overcomplicating
			the logging system for cred-stack as I really just want performant, production ready logging
		*/
		fileCore := zapcore.NewCore(
			zapcore.NewJSONEncoder(log.options.EncoderConfig),
			zapcore.AddSync(log.fp),
			log.options.LogLevel,
		)

		// If we are using file based logging then we need to overwrite our existing core
		core = zapcore.NewTee(consoleCore, fileCore)
	}

	/*
		Finally, we pass all of our created cores into Zap.New for zap to initialize the logger
	*/
	log.log = zap.New(core, zap.AddCaller())

	return log, nil
}
