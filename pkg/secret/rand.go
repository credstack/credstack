package secret

import (
	"crypto/rand"
)

/*
RandBytes - A function for generating cryptographically secure, random byte arrays of a fixed
size. Most commonly used for generating Argon2 hashes, or secured version 5 UUIDs. The error returned
from this function can be safely ignored as it is passed directly from rand.Read
*/
func RandBytes(length uint32) ([]byte, error) {
	ret := make([]byte, length)

	/*
		Fill the created byte array with cryptographically secured data. n is used as an offset
		for the byte array
	*/
	_, err := rand.Read(ret)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

/*
RandString - Generates a base64 encoded string that was generated with a cryptographically secure byte array. This is
primarily used for client ID generation for the application struct, but can be used in other situations
*/
func RandString(length uint32) (string, error) {
	data, err := RandBytes(length)
	if err != nil {
		return "", err
	}

	return EncodeBase64(data), nil
}
