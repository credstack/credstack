package client

import (
	"context"

	"github.com/credstack/credstack/internal/repository"
	"github.com/credstack/credstack/internal/secret"
	"github.com/credstack/credstack/pkg/models/header"
	"github.com/credstack/credstack/pkg/models/oauth/client"
	"github.com/credstack/credstack/pkg/server"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Service Represents the OAuth Client Service
type Service struct {
	repository *repository.Repository[client.Client]
}

// Get Returns a OAuth Client for a given client_id
func (svc *Service) Get(ctx context.Context, clientId string) (*client.Client, error) {
	ret, err := svc.repository.Get(ctx, bson.M{"client_id": clientId})
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// List Returns all OAuth clients available in the database
func (svc *Service) List(ctx context.Context, limit int) ([]*client.Client, error) {
	ret, err := svc.repository.List(ctx, limit)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// Delete Remove a single OAuth client from the database
func (svc *Service) Delete(ctx context.Context, clientId string) error {
	if _, err := svc.repository.Delete(ctx, bson.M{"client_id": clientId}); err != nil {
		return err
	}

	return nil
}

// Update Updates the attributes of a single OAuth Client. The following fields can be modified:
//
//	name, is_public, redirect_uri, token_lifetime, grant_type, allowed_audiences
func (svc *Service) Update(ctx context.Context, clientId string, patch *client.Client) error {
	patchFunc := func(patch *client.Client) bson.M {
		update := make(bson.M)

		if patch.Name != "" {
			update["name"] = patch.Name
		}

		if patch.IsPublic {
			update["is_public"] = patch.IsPublic
		}

		if patch.RedirectURI != "" {
			update["redirect_uri"] = patch.RedirectURI
		}

		if patch.TokenLifetime != 0 {
			update["token_lifetime"] = patch.TokenLifetime
		}

		if len(patch.GrantTypes) != 0 {
			update["grant_type"] = patch.GrantTypes
		}

		if len(patch.AllowedAudiences) != 0 {
			update["allowed_audiences"] = patch.AllowedAudiences
		}

		return update
	}

	if err := svc.repository.Update(ctx, bson.M{"client_id": clientId}, patchFunc); err != nil {
		return err
	}

	return nil
}

// New Insert a new OAuth client into the database
func (svc *Service) New(ctx context.Context, ins *client.Client) error {
	clientId, err := secret.RandString(16)
	if err != nil {
		return err
	}

	clientSecret, err := secret.RandString(96)
	if err != nil {
		return err
	}

	ins.Header = header.New(clientId)
	ins.ClientId = clientId
	ins.ClientSecret = clientSecret

	// handle model validation here
	if err := ins.Validate(); err != nil {
		return err
	}

	if err := svc.repository.Create(ctx, ins); err != nil {
		return err
	}

	return nil
}

func New(server *server.Server) *Service {
	return &Service{
		repository: repository.New[client.Client](server.Database(), "client"),
	}
}
