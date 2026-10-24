package secret

import (
	"encoding/base64"
	"fmt"
)

func EncodeBase64(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func DecodeBase64(data []byte, length uint32) ([]byte, error) {
	decoded := make([]byte, length)

	n, err := base64.URLEncoding.Decode(decoded, data)
	if err != nil {
		return nil, fmt.Errorf("b64: failed to decode %v", err)
	}

	return decoded[:n], nil
}
