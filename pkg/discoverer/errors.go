package discoverer

import "fmt"

// CredentialsValidationError is returned when the provided Target credentials
// are invalid (e.g. null)
type CredentialsValidationError struct {
	message string
}

func (e CredentialsValidationError) Error() string {
	return fmt.Sprintf("Validation error with Target credentials: %s",
		e.message)
}
