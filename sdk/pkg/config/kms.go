package config

type KmsCredentials struct {
	// AccessKeyID - An IAM access key ID. Used for authentication to AWS KMS
	AccessKeyId string `mapstructure:"access_key_id"`

	// SecretaAccessKey - The IAM secret access key. Used for authentication to AWS KMS
	SecretAccessKey string `mapstructure:"secret_access_key"`
}

type KmsConfig struct {
	// Type - The type of the KMS provider that you want to use. Defaults to db
	Type string `mapstructure:"type"`

	// CloudCredentials - Provides credentials to your cloud KMS provider. Not needed when a DB key provider
	CloudCredentials KmsCredentials `mapstructure:"credentials"`
}

// DefaultKMSConfig - Initializes the KmsConfig structure with sane defaults
func DefaultKMSConfig() KmsConfig {
	return KmsConfig{
		Type: "db",
	}
}
