package jwk

import (
	"context"
	"errors"

	"github.com/credstack/credstack/internal/repository"
	"github.com/credstack/credstack/internal/server"
	"github.com/credstack/credstack/pkg/models/oauth/jwk"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type Service struct {
	// jwkRepository Repository for interacting with JWKs
	jwkRepository *repository.Repository[jwk.JSONWebKey]

	// keyRepository Repository for interacting with private keys
	keyRepository *repository.Repository[jwk.PrivateJSONWebKey]
}

// JWKS Return all JWKS in the database
//
// TODO: This is not filtering by `kty` right now and needs to
// TODO: Hardcoded limit of 10. Repo needs support for unlimited list. Users cannot create keys without a revoke/client creation so no need to limit
func (svc *Service) JWKS(ctx context.Context) (*jwk.JSONWebKeySet, error) {
	jwks, err := svc.jwkRepository.List(ctx, 10)
	if err != nil {
		return nil, err
	}

	return &jwk.JSONWebKeySet{Keys: jwks}, nil
}

// ActiveKey Returns the currently active key for the given algorithm and audience
func (svc *Service) ActiveKey(ctx context.Context, alg string, aud string) (*jwk.PrivateJSONWebKey, error) {
	key, err := svc.keyRepository.Get(ctx, bson.M{"is_current": true, "alg": alg, "audience": aud})
	if err != nil {
		return nil, err
	}

	return key, nil
}

// New Create a new JWK/PrivateKey and set it as the active key
func (svc *Service) New(ctx context.Context, alg string, aud string) (*jwk.JSONWebKey, *jwk.PrivateJSONWebKey, error) {
	privateKey, jwk, err := jwk.NewPrivateKey(aud)
	if err != nil {
		return nil, nil, err
	}

	if err := svc.keyRepository.Create(ctx, privateKey); err != nil {
		return nil, nil, err
	}

	if err := svc.jwkRepository.Create(ctx, jwk); err != nil {
		return nil, nil, err
	}

	return jwk, privateKey, nil
}

// Get Fetch a JWK by its KID
func (svc *Service) Get(ctx context.Context, kid string) (*jwk.JSONWebKey, error) {
	ret, err := svc.jwkRepository.Get(ctx, bson.M{"kid": kid})
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// Revoke Revokes all active keys. Does not create new active keys
//
// TODO: Revoke not implemented
func (svc *Service) Revoke(ctx context.Context, aud string) error {
	return errors.New("jwk: `Revoke` not implemented")
}

// RotateRevoke Revokes all active keys and replaces them with a new one
//
// TODO: RotateRevoke not implemented
func (svc *Service) RotateRevoke(ctx context.Context, aud string) error {
	return errors.New("jwk: `RotateRevoke` not implemented")
}

// New Initializes a new Service and returns a pointer to it
func New(server *server.Server) *Service {
	return &Service{
		jwkRepository: repository.New[jwk.JSONWebKey](server.Database(), "jwk"),
		keyRepository: repository.New[jwk.PrivateJSONWebKey](server.Database(), "key"),
	}
}
