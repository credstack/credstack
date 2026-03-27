package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/credstack/credstack/sdk/pkg/key"
	"github.com/credstack/credstack/sdk/pkg/oauth/jwk"
	"github.com/credstack/credstack/sdk/pkg/server"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// DatabaseKeyProvider Represents the default key provider. Any and all key operations are stored directly within
// MongoDB. The DatabaseKeyProvider provides little to no security directly and relies on security measures that
// are implemented at the database level
type DatabaseKeyProvider struct {
	database *server.Database
}

// generate Generates a new private key and inserts it into the database.
// TODO: This only supports RS256 for the time being
func (provider *DatabaseKeyProvider) generate(alg string, aud string, isCurrent bool) error {
	generatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privateKey := key.NewDatabasePrivateKey(generatedKey)
	privateKey.Alg = "RS256"
	privateKey.Aud = aud
	privateKey.IsCurrent = isCurrent

	_, err = provider.database.Collection("key").InsertOne(context.Background(), privateKey)
	if err != nil {
		return err
	}

	return nil
}

// Count Returns the current number of keys that are available for signing
func (provider *DatabaseKeyProvider) Count(alg string, aud string, revoked bool) (int, error) {
	query := bson.M{"alg": alg, "audience": aud}
	if revoked {
		query = bson.M{"revoked": true, "alg": alg, "audience": aud}
	}

	result, err := provider.database.Collection("key").CountDocuments(context.Background(), query)
	if err != nil {
		return 0, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	return int(result), nil
}

// ActiveKey Returns the currently active signing key for JWT's
// TODO: Add caching for most recent active key
func (provider *DatabaseKeyProvider) ActiveKey(alg string, aud string) (key.PrivateKey, error) {
	var activeKey key.DatabasePrivateKey

	/*
		The header.identifier field always represents our Key Identifiers (kid) so we can always safely lookup our key
		with this. Additionally, the same KID is used across both the JWK and the Private Key to simplify key access
	*/
	result := provider.database.Collection("key").FindOne(context.Background(), bson.M{"alg": alg, "is_current": true, "audience": aud})
	err := result.Decode(&activeKey)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrKeyNotExist
		}
	}

	return &activeKey, nil
}

// Rotate Rotates all private key's. Does not invalidate them for validation
func (provider *DatabaseKeyProvider) Rotate(alg string, aud string) error {
	_, err := provider.database.Collection("key").UpdateMany(
		context.Background(),
		bson.M{"is_current": true, "audience": aud, "alg": alg},
		bson.M{"is_current": false},
	)

	if err != nil { // named error here
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	err = provider.generate(alg, aud, true)
	if err != nil { // named error here
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	return nil
}

// RotateRevoke Rotates all private keys, and revokes previously used keys
func (provider *DatabaseKeyProvider) RotateRevoke(alg string, aud string) error {
	err := provider.Rotate(alg, aud)
	if err != nil { // named error here
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	_, err = provider.database.Collection("key").DeleteMany(
		context.Background(),
		bson.M{"is_current": false, "audience": aud, "alg": alg},
	)
	if err != nil { // named error here
		return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
	}

	return nil
}

// JWKS Returns the JWKS for the given audience and algorithm
func (provider *DatabaseKeyProvider) JWKS(alg string, aud string) (*jwk.JSONWebKeySet, error) {
	jwks := new(jwk.JSONWebKeySet)

	/*
		This function call is actually fairly simple, as all we really need to do here is list out the entire collection.
	*/
	cursor, err := provider.database.Collection("jwk").Find(context.Background(), bson.M{"kty": "RSA"})
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}
	}

	/*
		Then we simply just decode all the results into our slice and then return it.
	*/
	err = cursor.All(context.Background(), &jwks.Keys) // check here for proper errors
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return nil, fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrKeyNotExist
		}
	}

	return jwks, nil
}

// NewDatabaseKeyProvider Initializes a new database key provider
func NewDatabaseKeyProvider(database *server.Database) *DatabaseKeyProvider {
	return &DatabaseKeyProvider{
		database: database,
	}
}
