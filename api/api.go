package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/stevezaluk/credstack-lib/header"
	"github.com/stevezaluk/credstack-lib/internal"
	"github.com/stevezaluk/credstack-lib/proto/api"
	"github.com/stevezaluk/credstack-lib/server"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ErrApiAlreadyExists - Provides a named error for when you try to insert an API with a domain that already exists
var ErrApiAlreadyExists = internal.NewError(409, "API_ALREADY_EXIST", "api: API already exists under the specified domain")

/*
NewAPI - Creates a new API for use with credstack. While the application determines your use case for authentication,
the API controls both what claims get inserted into generated tokens, but also what token types you utilize. Additionally,
it controls if RBAC is enforced on the API (validation of scopes and roles). This gets disabled by default, to ensure
the caller is fully aware of how the API authenticates users.

Any errors propagated here are returned. Little validation needs to happen on this model, so it only ensures that you
do not try and insert an API with the same domain as an existing one
*/
func NewAPI(serv *server.Server, name string, domain string, tokenType api.TokenType) error {
	/*
		Not too much validation really needs to happen on the parameters for this function as both name
		and domain are arbitrary. The domain is really just used as the 'audience' claim in the generated
		tokens. Additionally, we have an enum defined for our tokenType which enforces validation for it
	*/
	newApi := &api.API{
		Header:       header.NewHeader(domain),
		Name:         name,
		Domain:       domain,
		TokenType:    tokenType,
		EnforceRbac:  false,
		Applications: []string{},
	}

	/*
		After we build our model, we can consume a single database call to insert our new model. We have unique indexes
		created on both the domain and header.Identifier fields.
	*/
	_, err := serv.Database().Collection("api").InsertOne(context.Background(), newApi)
	if err != nil {
		var writeError mongo.WriteException
		if errors.As(err, &writeError) {
			if writeError.HasErrorCode(11000) { // this code should probably be passed as a const from Database
				return ErrApiAlreadyExists
			}
		}

		/*
			If we don't get a write exception than some other error occurred, and we can just wrap the
			InternalDatabaseError and return it
		*/
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	return nil
}
