package token

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/stevezaluk/credstack-lib/internal"
	"time"
)

/*
NewClaims - Creates a new claims structure with required claims applied to it. All tokens get the following claims applied
to it: iss, aud, iat, nbf, and exp. No custom expiration dates are supported for now, and all tokens will expires 1 day
after they are issued
*/
func NewClaims(issuer string, audience string) jwt.MapClaims {
	currentTime := jwt.NewNumericDate(time.Unix(internal.UnixTimestamp(), 0))

	return jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"iat": currentTime,
		"nbf": currentTime,
		"exp": jwt.NewNumericDate(currentTime.Add(time.Hour)),
	}
}
