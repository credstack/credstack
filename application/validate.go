package application

import applicationModel "github.com/stevezaluk/credstack-lib/proto/application"

/*
ValidateAudience - Validates that an application is allowed to issue tokens for a specified audience. Returns true if it
is allowed, returns false otherwise. If a nil application is provided in the first argument, then false is also returned
*/
func ValidateAudience(app *applicationModel.Application, audience string) bool {
	if app == nil {
		return false
	}

	for _, aud := range app.AllowedAudiences {
		if audience == aud {
			return true
		}
	}

	return false
}

/*
ValidateGrantType - Validates that an application is allowed to issue tokens for a specific grant type. Returns true if it
is allowed, returns false otherwise. If a nil application is provided in the first argument, then false is also returned
*/
func ValidateGrantType(app *applicationModel.Application, grantType applicationModel.GrantTypes) bool {
	if app == nil {
		return false
	}

	for _, grant := range app.GrantType {
		if grant == grantType {
			return true
		}
	}

	return false
}
