package request

/*
UserRegisterRequest - Provides a way for user's to register there accounts on a service. Any values not provided in this
request must be modified after user-registration
*/
type UserRegisterRequest struct {
	// Email - The primary email address for the user. Must be unique
	Email string `json:"email" bson:"email"`

	// Username - The username of the user. Does not need to be unique as primary lookup for the user is done via email
	Username string `json:"username" bson:"username"`

	// Password - The plain text password for the user. Will be hashed on the server-side using Argonv2ID
	Password string `json:"password" bson:"password"`

	// PhoneNumber - The users phone number in the following format +1800-555-5555
	PhoneNumber string `json:"phone_number" bson:"phone_number"`
}
