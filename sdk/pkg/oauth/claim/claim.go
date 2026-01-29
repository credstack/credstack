package claim

import (
	internalTime "github.com/credstack/credstack/sdk/internal/time"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

/*
NewClaims - Creates a new claims structure with required claims applied to it. All tokens get the following claims applied
to it: iss, aud, kid, iat, nbf, and exp. No custom expiration dates are supported for now, and all tokens will expires 1 day
after they are issued
*/
func NewClaims(iss string, aud string, exp uint64) jwt.RegisteredClaims {
	currentTime := time.Unix(internalTime.UnixTimestamp(), 0)

	return jwt.RegisteredClaims{
		Issuer:    iss,
		Audience:  []string{aud},
		IssuedAt:  jwt.NewNumericDate(currentTime),
		NotBefore: jwt.NewNumericDate(currentTime),
		ExpiresAt: jwt.NewNumericDate(currentTime.Add(time.Duration(exp) * time.Second)),
	}
}

/*
NewClaimsWithSubject - Provides a simple wrapper around NewClaims and inserts the subject string into the structure. This
should be either a user ID or an application ID depending on the flow that was used
*/
func NewClaimsWithSubject(iss string, aud string, sub string, exp uint64) jwt.RegisteredClaims {
	ret := NewClaims(iss, aud, exp)
	ret.Subject = sub

	return ret
}
