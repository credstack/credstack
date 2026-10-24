package user

import (
	"context"

	"github.com/credstack/credstack/internal/credential"
	"github.com/credstack/credstack/internal/repository"
	"github.com/credstack/credstack/internal/server"
	"github.com/credstack/credstack/pkg/models/header"
	"github.com/credstack/credstack/pkg/models/request"
	"github.com/credstack/credstack/pkg/models/user"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Service Represents the User service
type Service struct {
	server *server.Server

	repository *repository.Repository[user.User]
}

// List Lists all users in the database
func (svc *Service) List(ctx context.Context, limit int) ([]*user.User, error) {
	users, err := svc.repository.List(ctx, limit, "credential")
	if err != nil {
		return nil, err
	}

	return users, nil
}

// Get Fetch a single user in the database by email
func (svc *Service) Get(ctx context.Context, email string) (*user.User, error) {
	user, err := svc.repository.Get(ctx, bson.M{"email": email}, "credential")
	if err != nil {
		return nil, err
	}

	return user, nil
}

// Delete Remove a single user from the database
func (svc *Service) Delete(ctx context.Context, email string) error {
	if _, err := svc.repository.Delete(ctx, bson.M{"email": email}); err != nil {
		return err
	}

	return nil
}

// Update Update a single users metadata. Only honors the following fields: email
func (svc *Service) Update(ctx context.Context, email string, patch *user.User) error {
	patchFunc := func(patch *user.User) bson.M {
		update := make(bson.M)

		if patch.Email != "" {
			update["email"] = patch.Email
		}

		return update
	}

	if err := svc.repository.Update(ctx, bson.M{"email": email}, patchFunc); err != nil {
		return err
	}

	return nil
}

// Register Registers a new user and stores it in the database
func (svc *Service) Register(ctx context.Context, req *request.UserRegisterRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}

	credential, err := credential.New(req.Password, svc.server.Config.CredentialConfig)
	if err != nil {
		return err
	}

	ins := &user.User{
		Header:     header.New(req.Email),
		Email:      req.Email,
		Credential: credential,
		Roles:      []string{},
		Scopes:     []string{},
	}

	if err := svc.repository.Create(ctx, ins); err != nil {
		return err
	}

	return nil
}

// New Initializes a new Service and returns a pointer to it
func New(server *server.Server) *Service {
	return &Service{
		server:     server,
		repository: repository.New[user.User](server.Database(), "user"),
	}
}
