package token

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/stevezaluk/credstack-lib/internal"
	"time"
)

/*
NewClaims - Creates a new claims structure with required claims applied to it. All tokens get the following claims applied
to it: iss, aud, kid, iat, nbf, and exp. No custom expiration dates are supported for now, and all tokens will expires 1 day
after they are issued
*/
func NewClaims(iss string, aud string, kid string) jwt.MapClaims {
	currentTime := jwt.NewNumericDate(time.Unix(internal.UnixTimestamp(), 0))

	return jwt.MapClaims{
		"iss": iss,
		"aud": aud,
		"kid": kid,
		"iat": currentTime,
		"nbf": currentTime,
		"exp": jwt.NewNumericDate(currentTime.Add(time.Hour)),
	}
}

/*
NewClaimsWithSubject - Provides a simple wrapper around NewClaims and inserts the subject string into the structure. This
should be either a user ID or an application ID depending on the flow that was used
*/
func NewClaimsWithSubject(iss string, aud string, kid string, sub string) jwt.MapClaims {
	ret := NewClaims(iss, aud, kid)
	ret["sub"] = sub

	return ret
}
