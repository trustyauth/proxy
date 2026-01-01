package email

import "net/mail"

// IsValid returns true if the email address is valid.
func IsValid(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
