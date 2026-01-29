package options

import (
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"strings"
)

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
	LogLevel zapcore.Level

	// EncoderConfig - Provides universal configuration options for both stdout logggin and file logging
	EncoderConfig zapcore.EncoderConfig
}

/*
Log - Returns a LogOptions structure with some sensible defaults. File logging is disabled by default
to avoid adding un-needed complexity.
*/
func Log() *LogOptions {
	return &LogOptions{
		UseFileLogging: false,
		LogPath:        os.Getenv("HOME") + "/.credstack/logs",
		LogLevel:       zapcore.InfoLevel,
		EncoderConfig:  zap.NewProductionEncoderConfig(),
	}
}

/*
FromConfig - Fills in all fields present in the LogOptions structure with viper.
Any previously present configuration values will be overwritten this call. If an invalid log level
is passed into viper, it is set to zapcore.InfoLevel instead
*/
func (opts *LogOptions) FromConfig() *LogOptions {
	logLevel, err := zapcore.ParseLevel(viper.GetString("log.level"))
	if err != nil {
		logLevel = zapcore.InfoLevel
	}

	return &LogOptions{
		UseFileLogging: viper.GetBool("log.use_file_logging"),
		LogPath:        viper.GetString("log.path"),
		LogLevel:       logLevel,
		EncoderConfig:  zap.NewProductionEncoderConfig(),
	}
}

/*
SetFileLogging - If set to true, logs will be written to JSON files specified at
LogOptions.LogPath
*/
func (opts *LogOptions) SetFileLogging(value bool) *LogOptions {
	opts.UseFileLogging = value
	return opts
}

/*
SetPath - Sets the path that credstack should write log files to. This will not be evaluated unless
LogOptions.UseFileLogging is set to true. Paths that contain a tilda (~) that are passed here are
expanded to their absolute paths. If the path provided here is not found then logs are written to: ~/.credstack/logs
*/
func (opts *LogOptions) SetPath(path string) *LogOptions {
	if strings.HasPrefix(path, "~") {
		strings.Replace(path, "~", os.Getenv("HOME"), -1)
	}

	opts.LogPath = path
	if _, err := os.Stat(path); os.IsNotExist(err) {
		opts.LogPath = os.Getenv("HOME") + "/.credstack/logs"
	}

	return opts
}

/*
SetLogLevel - Sets the log level for both stdout logging and file logging. The possible values for
this are Info, Debug, and All. If an invalid value is passed here, then it defaults to Info. Please see
the constants defined here for using this
*/
func (opts *LogOptions) SetLogLevel(level zapcore.Level) *LogOptions {
	opts.LogLevel = level

	return opts
}

/*
SetEncoderConfig - Sets the specified Zap Encoder Configuration for the logger. This is used primarily
for file logging as it is a requirement for tree-ing together multiple loggers (like stdout and file)
*/
func (opts *LogOptions) SetEncoderConfig(config zapcore.EncoderConfig) *LogOptions {
	opts.EncoderConfig = config
	return opts

}
