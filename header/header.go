package header

import (
	"github.com/credstack/credstack-lib/internal"
	"github.com/credstack/credstack-lib/proto/header"
	"github.com/credstack/credstack-lib/secret"
)

/*
NewHeader - Generates a new header that can be attached to any cred-stack object. The basis that is provided in the
parameter of the function, is used for generating a version 5 UUID. Ideally, this should be a unique, immutable value
to protect against de-duplication.
*/
func NewHeader(basis string) *header.Header {
	/*
		Normally, I would inline this function call into each of the fields of the header.Header struct
		however doing that could present slight discrepancies in each timestamp
	*/
	timestamp := internal.UnixTimestamp()

	return &header.Header{
		Identifier: secret.GenerateUUID(basis),
		CreatedAt:  timestamp,
		UpdatedAt:  timestamp,
		AccessedAt: timestamp,
		Tags:       make(map[string]string),
	}
}
