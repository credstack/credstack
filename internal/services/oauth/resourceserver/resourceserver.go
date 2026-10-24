package resourceserver

import (
	"context"

	"github.com/credstack/credstack/internal/repository"
	"github.com/credstack/credstack/internal/server"
	"github.com/credstack/credstack/internal/services/oauth/jwk"
	"github.com/credstack/credstack/pkg/models/header"
	"github.com/credstack/credstack/pkg/models/oauth/resourceserver"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type Service struct {
	repository *repository.Repository[resourceserver.ResourceServer]
	jwkService *jwk.Service
}

// Get Fetch a resource server by audience
func (svc *Service) Get(ctx context.Context, aud string) (*resourceserver.ResourceServer, error) {
	rs, err := svc.repository.Get(ctx, bson.M{"audience": aud})
	if err != nil {
		return nil, err
	}

	return rs, nil
}

// List List all resource servers in the database
func (svc *Service) List(ctx context.Context, limit int) ([]*resourceserver.ResourceServer, error) {
	rs, err := svc.repository.List(ctx, limit)
	if err != nil {
		return nil, err
	}

	return rs, nil
}

// Delete Remove a resource server from the database
func (svc *Service) Delete(ctx context.Context, aud string) error {
	if _, err := svc.repository.Delete(ctx, bson.M{"audience": aud}); err != nil {
		return err
	}

	return nil
}

// Update Update a single resource server. Only the following fields are honored: name, enforce_rbac, token_type
func (svc *Service) Update(ctx context.Context, aud string, patch *resourceserver.ResourceServer) error {
	patchFunc := func(patch *resourceserver.ResourceServer) bson.M {
		update := make(bson.M)

		update["enforce_rbac"] = patch.EnforceRBAC
		update["token_type"] = patch.TokenType

		if patch.Name != "" {
			update["name"] = patch.Name
		}

		return update
	}

	if err := svc.repository.Update(ctx, bson.M{"audience": aud}, patchFunc); err != nil {
		return err
	}

	return nil
}

func (svc *Service) New(ctx context.Context, ins *resourceserver.ResourceServer) error {
	if err := ins.Validate(); err != nil {
		return err
	}

	ins.Header = header.New(ins.Audience)

	// JWKs are audience specific so each new resource server gets a new JWK that it can use
	if _, _, err := svc.jwkService.New(ctx, ins.Audience, ins.Audience); err != nil {
		return err
	}

	if err := svc.repository.Create(ctx, ins); err != nil {
		return err
	}

	return nil
}

func New(server *server.Server, jwkService *jwk.Service) *Service {
	return &Service{
		repository: repository.New[resourceserver.ResourceServer](server.Database(), "resource_server"),
		jwkService: jwkService,
	}
}
