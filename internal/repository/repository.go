package repository

import (
	"context"

	"github.com/credstack/credstack/pkg/server"
	"go.mongodb.org/mongo-driver/v2/bson"
	mongoOpts "go.mongodb.org/mongo-driver/v2/mongo/options"
)

type PatchFunc[T any] func(T) bson.M

// Repository An abstraction capable of performing basic CRUD operations on top of Mongo
type Repository[T any] struct {
	db *server.Database

	coll string
}

// Get Returns the first instance of an object according to a filter.
func (repo *Repository[T]) Get(ctx context.Context, filter bson.M, projection ...string) (*T, error) {
	projections := bson.M{}
	for _, value := range projection {
		projections[value] = 0
	}

	// Needs to support projections here
	result := repo.db.Collection(repo.coll).FindOne(
		ctx,
		filter,
		mongoOpts.FindOne().SetProjection(projections),
	)

	ret := new(T)
	if err := result.Decode(ret); err != nil {
		return nil, err
	}

	return ret, nil
}

// List Return all the objects in a collection with an enforced limit
func (repo *Repository[T]) List(ctx context.Context, limit int, projection ...string) ([]*T, error) {
	projections := bson.M{}
	for _, value := range projection {
		projections[value] = 0
	}

	result, err := repo.db.Collection(repo.coll).Find(
		ctx,
		bson.M{},
		mongoOpts.Find().SetLimit(int64(limit)).SetProjection(projections),
	)
	if err != nil {
		return nil, err
	}

	ret := make([]*T, 0, limit)
	if err := result.All(ctx, ret); err != nil {
		return nil, err
	}

	return ret, nil
}

// Delete Remove the first instance of an object from a collection according to the filter
func (repo *Repository[T]) Delete(ctx context.Context, filter bson.M) (int, error) {
	result, err := repo.db.Collection(repo.coll).DeleteOne(
		ctx,
		filter,
	)
	if err != nil {
		return 0, err
	}

	return int(result.DeletedCount), nil
}

// Create Insert a single object into Mongo at the collection specified during creation
func (repo *Repository[T]) Create(ctx context.Context, v *T) error {
	_, err := repo.db.Collection(repo.coll).InsertOne(
		ctx,
		v,
	)
	if err != nil {
		return err
	}

	return nil
}

// Update Update a single object in Mongo
func (repo *Repository[T]) Update(ctx context.Context, filter bson.M, patch PatchFunc[T]) error {
	_, err := repo.db.Collection(repo.coll).UpdateOne(
		ctx,
		filter,
		bson.M{"$set": patch},
	)
	if err != nil {
		return err
	}

	return nil
}

// New Initializes a new repository and returns a pointer to it
func New[T any](db *server.Database, collection string) *Repository[T] {
	return &Repository[T]{
		db:   db,
		coll: collection,
	}
}
