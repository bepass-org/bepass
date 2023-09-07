// Package socks5 provides functionality for handling SOCKS5 protocol authentication methods,
// including interfaces and implementations for credential stores.
package socks5

// CredentialStore is used to support user/pass authentication with optional network address validation.
// If you want to limit user network addresses, you can use this interface to implement custom validation logic.
type CredentialStore interface {
	Valid(user, password, userAddr string) bool
}

// StaticCredentials enables using a map directly as a credential store for simple username/password authentication.
type StaticCredentials map[string]string

// Valid implements the CredentialStore interface to validate user credentials.
func (s StaticCredentials) Valid(user, password, _ string) bool {
	pass, ok := s[user]
	return ok && password == pass
}
