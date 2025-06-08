package api

import (
	"context"
	"errors"
	"fmt"
	credstackError "github.com/stevezaluk/credstack-lib/errors"
	"github.com/stevezaluk/credstack-lib/header"
	"github.com/stevezaluk/credstack-lib/proto/api"
	"github.com/stevezaluk/credstack-lib/server"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ErrApiAlreadyExists - Provides a named error for when you try to insert an API with a domain that already exists
var ErrApiAlreadyExists = credstackError.NewError(409, "API_ALREADY_EXIST", "api: API already exists under the specified domain")

// ErrApiDoesNotExist - Provides a named error for when you try and fetch an API with a domain that does not exist
var ErrApiDoesNotExist = credstackError.NewError(404, "API_DOES_NOT_EXIST", "api: API does not exist under the specified domain")

// ErrApiMissingIdentifier - Provides a named error for when you try and insert or fetch an API with no domain or name
var ErrApiMissingIdentifier = credstackError.NewError(400, "API_MISSING_ID", "api: API is missing a domain identifier or a name")

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
		We always want to check to make sure both of these are filled in as we need a domain to use in the audience
		of our token
	*/
	if name == "" || domain == "" {
		return ErrApiMissingIdentifier
	}

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

/*
GetAPI - Fetches an API document from the database and marshals it into a API protobuf. The domain parameter
cannot be an empty string, but does not need to be a valid domain as this is used merely as an identifier. Named
errors are propagated here and returned. If an error occurs, API is returned as nil
*/
func GetAPI(serv *server.Server, domain string) (*api.API, error) {
	/*
		We must have a valid domain here. You are unable to insert an API with an empty domain, so this
		must be filled
	*/
	if domain == "" {
		return nil, ErrApiMissingIdentifier
	}

	result := serv.Database().Collection("api").FindOne(
		context.Background(),
		bson.M{"domain": domain},
	)

	var ret api.API

	/*
		We want to check for any errors in the decode process as we want to ensure that we catch
		any database errors, or any errors if there are no documents in the return value
	*/
	err := result.Decode(&ret)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrApiDoesNotExist
		}
	}

	return &ret, nil
}

/*
UpdateAPI - Provides functionality for updating the API connected to the given domain. Only the
following fields can be updated here: Name, TokenType, EnforceRBAC, and Applications. To update
any other fields, you must delete the existing API and then re-create it. The domain field is
never mutable as this is used as the basis for header.Identifier
*/
func UpdateAPI(serv *server.Server, domain string, patch *api.API) error {
	if domain == "" {
		return ErrApiMissingIdentifier
	}

	/*
		buildApiPatch - Provides a sub-function to convert the given api model into a bson.M struct that can be
		provided to mongo.UpdateOne. Only specified fields are supported in this function, so not all are included
		here
	*/
	buildApiPatch := func(patch *api.API) bson.M {
		update := make(bson.M)

		update["enforce_rbac"] = patch.EnforceRbac
		update["token_type"] = patch.TokenType

		if patch.Name != "" {
			update["name"] = patch.Name
		}

		if len(patch.Applications) != 0 {
			update["applications"] = patch.Applications
		}

		return update
	}

	result, err := serv.Database().Collection("api").UpdateOne(
		context.Background(),
		bson.M{"domain": domain},
		bson.M{"$set": buildApiPatch(patch)},
	)

	if err != nil {
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	if result.MatchedCount == 0 {
		return ErrApiDoesNotExist
	}

	return nil
}

/*
DeleteAPI - Completely removes the API from Credstack. A valid, non-empty domain must be provided here
to serve as the lookup key. If DeletedCount == 0 here, then the API is considered not to exist. Any other errors here
are propagated through the error return type
*/
func DeleteAPI(serv *server.Server, domain string) error {
	if domain == "" {
		return ErrApiMissingIdentifier
	}

	result, err := serv.Database().Collection("api").DeleteOne(
		context.Background(),
		bson.M{"domain": domain},
	)

	if err != nil {
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	if result.DeletedCount == 0 {
		return ErrApiDoesNotExist
	}

	return nil
}
