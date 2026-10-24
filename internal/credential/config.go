package credential

// Config Allows you to control configuration options for how user passwords are hashed with Argon
type Config struct {
	// Time The number of iterations that the argon algorithm will run
	Time uint32 `json:"time" yaml:"time" mapstructure:"time"`

	// Memory The maximum amount of memory (in Megabytes) that Argon can use to hash secrets
	Memory uint32 `json:"memory" yaml:"memory" mapstructure:"memory"`

	// Threads The number of threads to use when hashing secrets
	Threads uint8 `json:"threads" yaml:"threads" mapstructure:"threads"`

	// KeyLength The length of the hash that Argon will produce
	KeyLength uint32 `json:"key_length" yaml:"key_length" mapstructure:"key_length"`

	// SaltLength The length of the hash that Argon will use when hashing passwords
	SaltLength uint32 `json:"salt_length" yaml:"salt_length" mapstructure:"salt_length"`

	// MinSecretLength Sets the minimum password length that a new user must provide. Defaults to 12
	MinSecretLength uint32 `json:"min_secret_length" yaml:"min_secret_length" mapstructure:"min_secret_length"`

	// MaxSecretLength Sets the maximum password length that a new user must provide. Defaults to 48
	MaxSecretLength uint32 `json:"max_secret_length" yaml:"max_secret_length" mapstructure:"max_secret_length"`
}

// DefaultCredentialConfig Initializes the CredentialConfig structure with sane defaults
func DefaultConfig() Config {
	return Config{
		Time:            1,
		Memory:          1024,
		Threads:         1,
		KeyLength:       16,
		SaltLength:      32,
		MinSecretLength: 12,
		MaxSecretLength: 48,
	}
}
