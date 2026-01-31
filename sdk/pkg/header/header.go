package header

import (
	internalTime "github.com/credstack/credstack/sdk/internal/time"
	"github.com/credstack/credstack/sdk/pkg/secret"
)

/*
Header - A message representing shared data that is applied to all objects created by credstack. Primarily holds a
unique identifier that gets assigned to all user/system created objects, although also holds metadata such as timestamps
that can be shared across many different types of objects
*/
type Header struct {
	// Identifier - A UUID v5 based on an immutable property of the object this header is attached to.
	Identifier string `json:"identifier" bson:"identifier"`

	// CreatedAt - A unix timestamp representing when the object was created
	CreatedAt int64 `json:"created_at" bson:"created_at"`

	// UpdatedAt - A unix timestamp representing when the object was last updated
	UpdatedAt int64 `json:"updated_at" bson:"updated_at"`

	// AccessedAt - A unix timestamp representing when the object was last accessed
	AccessedAt int64 `json:"accessed_at" bson:"accessed_at"`

	// Tags - An arbitrary map of tags that can be assigned by the user
	Tags map[string]string `json:"tags" bson:"tags"`
}

/*
New - Generates a new header that can be attached to any cred-stack object. The basis that is provided in the
parameter of the function, is used for generating a version 5 UUID. Ideally, this should be a unique, immutable value
to protect against de-duplication.
*/
func New(basis string) *Header {
	timestamp := internalTime.UnixTimestamp()

	return &Header{
		Identifier: secret.GenerateUUID(basis),
		CreatedAt:  timestamp,
		UpdatedAt:  timestamp,
		AccessedAt: timestamp,
		Tags:       make(map[string]string),
	}
}
