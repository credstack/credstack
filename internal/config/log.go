package config

import (
	"go.uber.org/zap/zapcore"
)

type LogConfig struct {
	// UseFileLogging - If set to true, log files will be written in JSON format
	UseFileLogging bool `mapstructure:"use_file_logging"`

	// LogPath - The directory that logs should be saved under
	LogPath string `mapstructure:"log_path"`

	// LogLevel - A string determining how verbose logs should be. Can be: Info (default), Debug, All
	LogLevel zapcore.Level

	// EncoderConfig - Provides universal configuration options for both stdout logggin and file logging
	EncoderConfig zapcore.EncoderConfig
}

// DefaultLogConfig Initializes the LogConfig structure with sane defaults
func DefaultLogConfig() LogConfig {
	return LogConfig{
		UseFileLogging: false,
		LogPath:        "/var/log/credstack",
		LogLevel:       zapcore.InfoLevel,
	}
}
