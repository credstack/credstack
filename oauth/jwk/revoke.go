package jwk

import (
	"context"
	"errors"
	"fmt"
	credstackError "github.com/credstack/credstack-lib/errors"
	"github.com/credstack/credstack-lib/server"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var ErrNoKeysToRevoke = credstackError.NewError(404, "ERR_NO_KEY_REVOKE", "jwk: There are no keys in the database to revoke")

/*
revokeAllKeys - Revokes all the keys for a given algorithm and given audience
*/
func revokeAllKeys(serv *server.Server, alg string, audience string) error {
	/*
		All we really need to do to "revoke" keys is set is_current to false. This marks the key as not available for
		signing new tokens, as only one of these can be present at a time

		This function is really only a helper function for RotateKeys and RotateRevokeKeys
	*/
	result, err := serv.Database().Collection("key").UpdateMany(context.Background(), bson.M{"alg": alg, "audience": audience}, bson.M{"$set": bson.M{"is_current": false}})
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) && err != nil {
			return fmt.Errorf("%w (%v)", server.ErrInternalDatabase, err)
		}
	}

	if result.MatchedCount == 0 {
		return ErrNoKeysToRevoke
	}

	return nil
}

/*
RotateKeys - Marks all private keys in the database as not available for signing and generates a new key. The new key
generated here is automatically marked as available for signing and any new tokens issues post-function call will use
this key to sign tokens

This differs from RotateRevokeKeys, as this function leaves the JWK's associated with them in the jwk collection. This
means that they can still be fetched under .well-known/jwks.json and any tokens signed with old keys are still considered
'valid'
*/
func RotateKeys(serv *server.Server, alg string, audience string) error {
	/*
		First we need to mark any old keys as not available for signing. This is consumed with one database call using
		UpdateMany.

		This can be a potential point of failure as if NewKey fails, then no keys exist for signing
	*/
	err := revokeAllKeys(serv, alg, audience)
	if err != nil {
		return err
	}

	/*
		Then we simply just generate our new key
	*/
	_, err = NewKey(serv, alg, audience)
	if err != nil {
		return err
	}

	return nil
}
