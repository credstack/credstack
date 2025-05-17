package server

import "github.com/stevezaluk/credstack-lib/options"

/*
Log - An abstraction for the Logger. Handles any logic for creating and writing log files here
*/
type Log struct {
	// options -
	options *options.LogOptions
}

/*
NewLog - Constructs a new Log using the values passed in its parameters. If an options structure is not passed in this
functions parameter, then the Log is initialized with default values. Additionally, if more than 1 are passed here,
only the first is used.
*/
func NewLog(opts ...*options.LogOptions) *Log {
	if len(opts) == 0 {
		opts = append(opts, new(options.LogOptions))
	}

	return &Log{
		options: opts[0],
	}
}
