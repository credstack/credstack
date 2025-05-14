package options

/*
LogOptions - A container for any configurable options for the Zap Logger. Not
a lot of options are exposed here as the logger isn't designed to be very
featureful.
*/
type LogOptions struct {
	// UseFileLogging - If set to true, log files will be written in JSON format
	UseFileLogging bool

	// LogPath - The directory that logs should be saved under
	LogPath string

	// LogLevel - A string determining how verbose logs should be. Can be: Info (default), Debug, All
	LogLevel string
}

/*
Log - Returns a LogOptions structure with some sensible defaults. File logging is disabled by default
to avoid adding un-needed complexity.
*/
func Log() *LogOptions {
	return &LogOptions{
		UseFileLogging: false,
		LogPath:        "/.credstack/logs",
		LogLevel:       "", // change this
	}
}
