package config

type CredentialConfig struct {
	// Time - The number of iterations that the argon algorithm will run
	Time uint32

	// Memory - The maximum amount of memory (in Megabytes) that Argon can use to hash secrets
	Memory uint32

	// Threads - The number of threads to use when hashing secrets
	Threads uint8

	// KeyLength - The length of the hash that Argon will produce
	KeyLength uint32

	// SaltLength - The length of the hash that Argon will use when hashing passwords
	SaltLength uint32

	// MinSecretLength - Sets the minimum password length that a new user must provide. Defaults to 12
	MinSecretLength uint32

	// MaxSecretLength - Sets the maximum password length that a new user must provide. Defaults to 48
	MaxSecretLength uint32
}
