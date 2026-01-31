package config

import "github.com/spf13/viper"

type ServerConfig struct {
	// viper The viper instance that will store configuration values
	viper *viper.Viper
}

// New Initialize a new ServerConfig structure
func New() *ServerConfig {
	return &ServerConfig{viper: viper.New()}
}
