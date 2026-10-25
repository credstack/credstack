package token

import (
	"time"

	"github.com/credstack/credstack/pkg/models/response"
)

// Token Represents a JWT issued to a caller
type Token struct {
	// Subject The subject the token was issued for. Can be a user ID or a client ID
	Subject string `json:"sub" bson:"sub"`

	// ClientId The client ID of the OAuth client that issued the token
	ClientId string `json:"client_id" bson:"client_id"`

	// AccessToken The access token that was issued
	AccessToken string `json:"access_token" bson:"access_token"`

	// RefreshToken The refresh token that was issued
	RefreshToken string `json:"refresh_token" bson:"refresh_token"`

	// IdToken The ID token that was issued
	IdToken string `json:"id_token" bson:"id_token"`

	// ExpiresIn The time in seconds that the token expires in
	ExpiresIn int `json:"expires_in" bson:"expires_in"`

	// ExpiresAt A timestamp that represents the datetime in which the access token expires
	ExpiresAt time.Time `json:"expires_at" bson:"expires_at"`

	// RefreshExpiresAt A timestamp that represents the datetime in which the refresh token expires
	RefreshExpiresAt time.Time `json:"refresh_expires_at" bson:"refresh_expires_at"`

	// Scope Any permission scopes that were issued with the token
	Scope string `json:"scope" bson:"scope"`
}

// Response Takes a token and returns it as a response.TokenResponse
func (token *Token) Response() *response.TokenResponse {
	return &response.TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    token.ExpiresIn,
		IdToken:      token.IdToken,
		RefreshToken: token.RefreshToken,
		Scope:        token.Scope,
	}
}
