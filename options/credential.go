package options

import "github.com/spf13/viper"

type CredentialOptions struct {
	// Time - The number of iterations that the argon algorithm will run
	Time int

	// Memory - The maximum amount of memory (in Megabytes) that Argon can use to hash secrets
	Memory uint32

	// Threads - The number of threads to use when hashing secrets
	Threads uint8

	// Length - The length of the hash that Argon will produce
	Length uint32
}

/*
Credential - Initializes a new CredentialOptions struct with sane defaults that can be applied
*/
func Credential() *CredentialOptions {
	return &CredentialOptions{
		Time:    1,
		Memory:  16 * 1024,
		Threads: 1,
		Length:  16,
	}
}

/*
FromConfig - Initializes CredentialOptions using values provided by Viper. Overwrites any previous options
that were set
*/
func (opts *CredentialOptions) FromConfig() *CredentialOptions {
	return &CredentialOptions{
		Time:    viper.GetInt("argon.time"),
		Memory:  viper.GetUint32("argon.memory"),
		Threads: viper.GetUint8("argon.threads"),
		Length:  viper.GetUint32("argon.length"),
	}
}
