package middleware

import (
	"errors"

	"github.com/credstack/credstack/internal/repository" // this needs to be fixed
	"github.com/gin-gonic/gin"
)

// HandleError Unwrap a given error and process it for common database errors, or validation errors
func HandleError(c *gin.Context, err error) {
	if errors.Is(err, repository.ErrInternalDatabase) {
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal database error has occured"})
		return
	}

	if errors.Is(err, repository.ErrDuplicateObject) {
		c.AbortWithStatusJSON(409, gin.H{"error": "Duplicated object cannot be created"})
		return
	}

	if errors.Is(err, repository.ErrNoObjectFound) {
		c.AbortWithStatusJSON(404, gin.H{"error": "Failed to find object under the specified lookup key"})
		return
	}

	// TODO: Handle validation errors here
	//

	if err != nil {
		c.AbortWithStatusJSON(500, gin.H{"error": "Unknown sentinel error returned: %v" + err.Error()})
		return
	}
}
