package flow

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/credstack/credstack/internal/services/oauth/client"
	"github.com/credstack/credstack/internal/services/oauth/jwk"
	"github.com/credstack/credstack/internal/services/oauth/resourceserver"
	"github.com/credstack/credstack/internal/services/oauth/token"
	clientModel "github.com/credstack/credstack/pkg/models/oauth/client"
	"github.com/credstack/credstack/pkg/models/request"
	"github.com/credstack/credstack/pkg/models/response"
	"github.com/credstack/credstack/pkg/server"
)

var (
	ErrInvalidClientCredentials = errors.New("flow: Invalid client credentials provided")
)

type Service struct {
	resourceServerService *resourceserver.Service
	clientService         *client.Service
	tokenService          *token.Service
}

// ClientCredentials Compare a user provided secret with the store client secret
func (svc *Service) ClientCredentials(secret string, client *clientModel.Client) error {
	if subtle.ConstantTimeCompare([]byte(secret), []byte(client.ClientSecret)) != 1 {
		return ErrInvalidClientCredentials // TODO: Named error here
	}

	return nil
}

// IssueToken Issues a token for the given authentication flow
//
// TODO: This will always fail validation since svc.clientService.Get does not return a client secret
// TODO: Issuer should represent our hostname or should be configurable
func (svc *Service) IssueToken(ctx context.Context, req *request.TokenRequest) (*response.TokenResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	switch req.GrantType {
	case "client_credentials":
		requestedClient, err := svc.clientService.Get(ctx, req.ClientId)
		if err != nil {
			return nil, err
		}

		if err := svc.ClientCredentials(req.ClientSecret, requestedClient); err != nil {
			return nil, err
		}

		rs, err := svc.resourceServerService.Get(ctx, req.Audience)
		if err != nil {
			return nil, err
		}

		tok, err := svc.tokenService.RS256(ctx, "https://credstack.local", rs.Audience, requestedClient.TokenLifetime)
		if err != nil {
			return nil, err
		}

		return tok.Response(), nil
	}

	return nil, nil
}

func New(server *server.Server) *Service {
	return &Service{
		resourceServerService: resourceserver.New(server, jwk.New(server)),
		clientService:         client.New(server),
		tokenService:          token.New(server),
	}
}
