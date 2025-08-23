package api

import (
	"context"
	"errors"
	"fmt"

	credstackError "github.com/credstack/credstack/pkg/errors"
	"github.com/credstack/credstack/pkg/header"
	"github.com/credstack/credstack/pkg/oauth/application"
	"github.com/credstack/credstack/pkg/oauth/jwk"
	"github.com/credstack/credstack/pkg/oauth/token"
	"github.com/credstack/credstack/pkg/server"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongoOpts "go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	// TokenTypeHS256 - A constant string representing the HS256 token signing method
	TokenTypeHS256 string = "HS256"

	// TokenTypeRS256 - A constant string representing the RS256 token signing method
	TokenTypeRS256 string = "RS256"
)

// ErrApiAlreadyExists - Provides a named error for when you try to insert an API with a domain that already exists
var ErrApiAlreadyExists = credstackError.NewError(409, "API_ALREADY_EXIST", "api: API already exists under the specified domain")

// ErrApiDoesNotExist - Provides a named error for when you try and fetch an API with a domain that does not exist
var ErrApiDoesNotExist = credstackError.NewError(404, "API_DOES_NOT_EXIST", "api: API does not exist under the specified domain")

// ErrApiMissingIdentifier - Provides a named error for when you try and insert or fetch an API with no domain or name
var ErrApiMissingIdentifier = credstackError.NewError(400, "API_MISSING_ID", "api: API is missing a domain identifier or a name")

/*
Api - Represents the OAuth resource server and contains metadata for validating tokens
*/
type Api struct {
	// header - The header for the API. Created at object birth
	Header *header.Header `json:"header" bson:"header"`

	// Name - The name of the API as defined by the user
	Name string `json:"name" bson:"name"`

	// Audience - A arbitrary domain used in the audience of issued tokens. Does not need to resolve to anything
	Audience string `json:"audience" bson:"audience"`

	// TokenType - The type of tokens that the API should validate
	TokenType string `json:"token_type" bson:"token_type"`

	// EnforceRBAC - If set to true, then the API will evaluate scopes and roles during validation (and will insert them as claims in the token)
	EnforceRBAC bool `json:"enforce_rbac" bson:"enforce_rbac"`
}

/*
GenerateToken - Generates a token based on the Application and API that are passed in the parameter. Claims that are passed
will be inserted into the generated token. Calling this function alone, does not store the tokens in the database and only
generates the token. An instantiated server structure needs to be passed here to ensure that we can fetch the current
active encryption key for token signing (RS256)
*/
func (api *Api) GenerateToken(serv *server.Server, application *application.Application, claims jwt.RegisteredClaims) (*token.Token, error) {
	var generatedToken *token.Token

	switch api.TokenType {
	case "RS256":
		privateKey, err := jwk.ActiveKey(serv, api.TokenType, api.Audience)
		if err != nil {
			return nil, err
		}

		tok, err := token.RS256(privateKey, claims, uint32(application.TokenLifetime))
		if err != nil {
			return nil, err
		}

		generatedToken = tok
	case "HS256":
		tok, err := token.HS256(application.ClientSecret, claims, uint32(application.TokenLifetime))
		if err != nil {
			return nil, err
		}

		generatedToken = tok
	}

	if generatedToken == nil {
		return nil, fmt.Errorf("%w (%v)", token.ErrFailedToSignToken, "Invalid Signing Algorithm")
	}

	return generatedToken, nil
}

/*
New - Creates a new API for use with credstack. While the application determines your use case for authentication,
the API controls both what claims get inserted into generated tokens, but also what token types you utilize. Additionally,
it controls if RBAC is enforced on the API (validation of scopes and roles). This gets disabled by default, to ensure
the caller is fully aware of how the API authenticates users.

Any errors propagated here are returned. Little validation needs to happen on this model, so it only ensures that you
do not try and insert an API with the same domain as an existing one

TODO: Update this to not generate a key everytime, only RS256 tokens need keys generated
*/
func New(serv *server.Server, name string, audience string, tokenType string) error {
	/*
		We always want to check to make sure both of these are filled in as we need a domain to use in the audience
		of our token
	*/
	if name == "" || audience == "" {
		return ErrApiMissingIdentifier
	}

	/*
		Not too much validation really needs to happen on the parameters for this function as both name
		and domain are arbitrary. The domain is really just used as the 'audience' claim in the generated
		tokens. Additionally, we have an enum defined for our tokenType which enforces validation for it
	*/
	newApi := &Api{
		Header:      header.New(audience),
		Name:        name,
		Audience:    audience,
		TokenType:   tokenType,
		EnforceRBAC: false,
	}

	/*
		We always need to generate a new key for the API to be able to use
	*/
	_, err := jwk.New(serv, newApi.TokenType, newApi.Audience)
	if err != nil {
		return err
	}

	/*
		After we build our model, we can consume a single database call to insert our new model. We have unique indexes
		created on both the domain and header.Identifier fields.
	*/
	_, err = serv.Database().Collection("api").InsertOne(context.Background(), newApi)
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
Get - Fetches an API document from the database and marshals it into a API protobuf. The domain parameter
cannot be an empty string, but does not need to be a valid domain as this is used merely as an identifier. Named
errors are propagated here and returned. If an error occurs, API is returned as nil
*/
func Get(serv *server.Server, audience string) (*Api, error) {
	/*
		We must have a valid domain here. You are unable to insert an API with an empty domain, so this
		must be filled
	*/
	if audience == "" {
		return nil, ErrApiMissingIdentifier
	}

	result := serv.Database().Collection("api").FindOne(
		context.Background(),
		bson.M{"audience": audience},
	)

	var ret Api

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
List - Lists all user defined API's present in the database. Optionally, a limit can be specified here to limit the
amount of data returned at once. The maximum that can be returned in a single call is 10, and if a limit exceeds this, it
will be reset to 10
*/
func List(serv *server.Server, limit int) ([]*Api, error) {
	if limit > 10 {
		limit = 10
	}

	result, err := serv.Database().Collection("api").Find(
		context.Background(),
		bson.M{},
		mongoOpts.Find().SetBatchSize(int32(limit)),
	)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	ret := make([]*Api, 0, limit)

	err = result.All(context.Background(), &ret)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrApiDoesNotExist
		}
	}

	return ret, nil
}

/*
Update - Provides functionality for updating the API connected to the given domain. Only the
following fields can be updated here: Name, TokenType, EnforceRBAC, and Applications. To update
any other fields, you must delete the existing API and then re-create it. The domain field is
never mutable as this is used as the basis for header.Identifier
*/
func Update(serv *server.Server, audience string, patch *Api) error {
	if audience == "" {
		return ErrApiMissingIdentifier
	}

	/*
		buildApiPatch - Provides a sub-function to convert the given api model into a bson.M struct that can be
		provided to mongo.UpdateOne. Only specified fields are supported in this function, so not all are included
		here
	*/
	buildApiPatch := func(patch *Api) bson.M {
		update := make(bson.M)

		update["enforce_rbac"] = patch.EnforceRBAC
		update["token_type"] = patch.TokenType

		if patch.Name != "" {
			update["name"] = patch.Name
		}

		return update
	}

	result, err := serv.Database().Collection("api").UpdateOne(
		context.Background(),
		bson.M{"audience": audience},
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
Delete - Completely removes the API from Credstack. A valid, non-empty domain must be provided here
to serve as the lookup key. If DeletedCount == 0 here, then the API is considered not to exist. Any other errors here
are propagated through the error return type
*/
func Delete(serv *server.Server, audience string) error {
	if audience == "" {
		return ErrApiMissingIdentifier
	}

	result, err := serv.Database().Collection("api").DeleteOne(
		context.Background(),
		bson.M{"audience": audience},
	)

	if err != nil {
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	if result.DeletedCount == 0 {
		return ErrApiDoesNotExist
	}

	return nil
}
