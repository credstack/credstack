package options

import "github.com/spf13/viper"

type CredentialOptions struct {
	// Time - The number of iterations that the argon algorithm will run
	Time uint32

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
		Time:    viper.GetUint32("argon.time"),
		Memory:  viper.GetUint32("argon.memory"),
		Threads: viper.GetUint8("argon.threads"),
		Length:  viper.GetUint32("argon.length"),
	}
}

/*
SetTime - Sets the number of iterations that the argon algorithm will apply to the secret. Generally,
this should be set to one but can be increased in more sensitive environments
*/
func (opts *CredentialOptions) SetTime(time uint32) *CredentialOptions {
	opts.Time = time
	return opts
}

/*
SetMemory - Sets the amount of memory that the Argon algorithm will consume during hashing operations. The `memory`
parameter should represent the number of megabytes you wish to set this to
*/
func (opts *CredentialOptions) SetMemory(memory uint32) *CredentialOptions {
	opts.Memory = memory * 1024
	return opts
}

/*
SetThreads - Sets the number of go-routines that will actively be used in hashing. This is set to 1 by default, however
if higher performance is requried this can be increased.
*/
func (opts *CredentialOptions) SetThreads(threads uint8) *CredentialOptions {
	opts.Threads = threads
	return opts
}

/*
SetLength - Sets the length in bytes that the generated hash should be. This is set to 16 by default
*/
func (opts *CredentialOptions) SetLength(length uint32) *CredentialOptions {
	opts.Length = length
	return opts
}
