package log

import (
	"log/slog"
	"os"
)

// Init Initializes slog with structured `stdout` logging
func Init(config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(config.Level)); err != nil {
		return err
	}

	slog.SetLogLoggerLevel(level)
	slog.SetDefault(
		slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	)

	return nil
}
