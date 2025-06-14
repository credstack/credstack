package key

import (
	credstackError "github.com/stevezaluk/credstack-lib/errors"
)

var ErrGenerateKey = credstackError.NewError(500, "ERR_GENERATING_KEY", "jwk: Failed to generate cryptographic key")
