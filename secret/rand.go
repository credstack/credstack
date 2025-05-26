package secret

import "crypto/rand"

/*
RandBytes - A function for generating cryptographically secure, random byte arrays of a fixed
size. Most commonly used for generating Argon2 hashes, or secured version 5 UUIDs. The error returned
from this function can be safely ignored as it is passed directly from rand.Read
*/
func RandBytes(length uint32) ([]byte, error) {
	ret := make([]byte, length)

	n, err := rand.Read(ret)
	if err != nil {
		return nil, err
	}

	return ret[:n], nil
}
