package credential

import (
	"fmt"

	"github.com/credstack/credstack/internal/secret"
	"github.com/credstack/credstack/pkg/config"
)

// Credential Represents a user's hashed password, along with the parameters used for hashing
type Credential struct {
	// Key The user's hashed password represented as a string
	Key string `bson:"key" json:"key"`

	// Salt A randomly generated string used for introducing a unique value to the generated key
	Salt string `bson:"salt" json:"salt"`

	// Time The cost parameter used by Argon when hashing passwords. Should be 1 usually
	Time uint32 `bson:"time" json:"time"`

	// Memory The amount of memory to be used when hashing passwords
	Memory uint32 `bson:"memory" json:"memory"`

	// Threads The number of go-routines (threads) to be used when hashing the user's password
	Threads uint32 `bson:"threads" json:"threads"`

	// KeyLength The length of the Argon generated key
	KeyLength uint32 `bson:"key_length" json:"key_length"`

	// SaltLength The length of the generated salt
	SaltLength uint32 `bson:"salt_length" json:"salt_length"`
}

// NewCredential Creates and generates a new UserCredential using the secret provided in the parameter. Both the secret
// and the salt are stored as URL-Safe, base64 encoded strings.
func New(credential string, config config.CredentialConfig) (*Credential, error) {
	hash, salt, err := secret.NewArgon2Hash([]byte(credential), config)
	if err != nil {
		return nil, fmt.Errorf("credential: Failed to hash user credential %v", err)
	}

	return &Credential{
		Key:        secret.EncodeBase64(hash),
		Salt:       secret.EncodeBase64(salt),
		Time:       config.Time,
		Memory:     config.Memory,
		Threads:    uint32(config.Threads),
		KeyLength:  config.KeyLength,
		SaltLength: config.SaltLength,
	}, nil
}

// CheckCredential Validates a user provided password with what is stored in the database
func CheckCredential(validate string, credential *Credential) error {
	decodedSalt, err := secret.DecodeBase64([]byte(credential.Salt), credential.SaltLength)
	if err != nil {
		return err
	}

	decodedHash, err := secret.DecodeBase64([]byte(credential.Key), credential.KeyLength)
	if err != nil {
		return err
	}

	isValid := secret.ValidateArgon2Hash([]byte(validate), decodedSalt, decodedHash, config.CredentialConfig{
		Time:      credential.Time,
		Memory:    credential.Memory,
		Threads:   uint8(credential.Threads),
		KeyLength: credential.KeyLength,
	})

	if !isValid {
		return fmt.Errorf("credential: Invalid user credentials provided")
	}

	return nil
}
