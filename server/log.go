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
