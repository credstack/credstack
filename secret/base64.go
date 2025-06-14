package secret

import (
	"encoding/base64"
	"fmt"
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	"math/big"
)

// ErrFailedToBaseDecode - Provides a named error for when base64 decoding data fails during a user credential validation
var ErrFailedToBaseDecode = credstackError.NewError(500, "FAILED_TO_BASE_DECODE", "user: failed to decode base64 data during user credential validation")

/*
EncodeBase64 - Encodes any data passed into the data parameter to a URL-Safe Base64 Encoded byte array
*/
func EncodeBase64(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

/*
DecodeBase64 - Decodes base64 data passed in the data parameter. A length is provided here to enforce specific
size requirements in the event that they are required.

Any errors propagated here are returned in the form of the named error: ErrFailedToBaseDecode. This error is wrapped,
so if you need to access the underlying error you can use errors.Unwrap
*/
func DecodeBase64(data []byte, length uint32) ([]byte, error) {
	decoded := make([]byte, length)

	n, err := base64.URLEncoding.Decode(decoded, data)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrFailedToBaseDecode, err)
	}

	return decoded[:n], nil
}
