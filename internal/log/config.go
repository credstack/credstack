package log

import (
	"github.com/go-playground/validator/v10"
)

// Config Logging configuration
type Config struct {
	// Level The slog level to record events at. Can be: debug, info, warn, error
	Level string `json:"level" yaml:"level" mapstructure:"level" validate:"required,oneof=debug info warn error"`
}

// Validate Ensures that the log config is validate
func (config *Config) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(config); err != nil {
		return err
	}

	return nil
}

// DefaultConfig Initializes the LogConfig structure with sane defaults
func DefaultConfig() Config {
	return Config{
		Level: "info",
	}
}
