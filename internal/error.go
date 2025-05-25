package internal

/*
CredstackError - Provides a custom error structure that provides more information regarding errors than the standard
error struct. This implemented the error interface so it can be use interchangeably with standard Go code
*/
type CredstackError struct {
	// HTTPStatusCode - The HTTP Status Code that correlates to this error
	HTTPStatusCode int

	// ShortCode - A string representing a shorter error message that can be used to validate the type of error
	ShortCode string

	// Message - A string representing the error message
	Message string
}

/*
HTTPCode - Returns the HTTP Status Code that correlates to this error
*/
func (err CredstackError) HTTPCode() int {
	return err.HTTPStatusCode
}

/*
Short - Provides the short code of the error in the form of a string
*/
func (err CredstackError) Short() string {
	return err.ShortCode
}

/*
Error - Returns the error message that is stored in the CredstackError struct. Required to implement the error interface
*/
func (err CredstackError) Error() string {
	return err.Message
}

/*
NewError - Provides a constructor for the CredstackError struct
*/
func NewError(statusCode int, shortCode string, message string) error {
	return CredstackError{
		HTTPStatusCode: statusCode,
		ShortCode:      shortCode,
		Message:        message,
	}
}
