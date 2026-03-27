package jwk

/*
JSONWebKeySet - Represents a list of public keys that can be used for validating token signatures
*/
type JSONWebKeySet struct {
	// Keys - All Keys available for signing under the set
	Keys []JSONWebKey `json:"keys" bson:"keys"`
}
