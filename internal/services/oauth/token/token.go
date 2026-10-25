package token

import (
	"context"
	"time"

	"github.com/credstack/credstack/internal/server"
	"github.com/credstack/credstack/internal/services/oauth/jwk"
	internal "github.com/credstack/credstack/internal/time" // rename to `time`
	tokenModel "github.com/credstack/credstack/pkg/models/oauth/token"
	"github.com/golang-jwt/jwt/v5"
)

type Service struct {
	jwkService *jwk.Service
}

// RegisteredClaims Returns the default set of registered claims that all tokens receive
func (svc *Service) registeredClaims(iss string, aud string, exp int) jwt.RegisteredClaims {
	currentTime := time.Unix(internal.UnixTimestamp(), 0)

	return jwt.RegisteredClaims{
		Issuer:    iss,
		Audience:  []string{aud},
		IssuedAt:  jwt.NewNumericDate(currentTime),
		NotBefore: jwt.NewNumericDate(currentTime),
		ExpiresAt: jwt.NewNumericDate(currentTime.Add(time.Duration(exp) * time.Second)),
	}
}

// RS256 Generates a signed RS256 token using the private key for a given audience
func (svc *Service) RS256(ctx context.Context, iss string, aud string, exp int) (*tokenModel.Token, error) {
	claims := svc.registeredClaims(iss, aud, exp)

	tok := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		claims,
	)

	privateKey, err := svc.jwkService.ActiveKey(ctx, "RS256", aud)
	if err != nil {
		return nil, err
	}

	rsa, err := privateKey.RSA()
	if err != nil {
		return nil, err
	}

	sig, err := tok.SignedString(rsa)
	if err != nil {
		return nil, err
	}

	return &tokenModel.Token{
		Subject:     claims.Subject,
		AccessToken: sig,
		ExpiresIn:   exp,
		ExpiresAt:   time.Now().UTC().Add(time.Duration(exp) * time.Second),
	}, nil
}

func New(server *server.Server) *Service {
	jwkService := jwk.New(server)
	return &Service{
		jwkService: jwkService,
	}
}
