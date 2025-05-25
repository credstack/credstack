package internal

import uuid2 "github.com/google/uuid"

/*
GenerateUUID - Generates a basic version 5 UUID to use in the header.Identifier field. The basis that is passed
in the parameter here is hashed along with the UUID namespace URL and a new UUID is generated from it. Using a
basis for this generation provides an additional layer of protection against duplication as if the same basis
is used, then the same UUID is generated
*/
func GenerateUUID(basis string) string {
	uuid := uuid2.NewSHA1(uuid2.NameSpaceURL, []byte(basis))

	return uuid.String()
}
