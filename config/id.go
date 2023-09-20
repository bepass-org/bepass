package config

import "math/rand"

var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-"

// ShortID generates a random short SessionID of the specified length.
func shortID(length int) string {
	ll := len(chars)
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	} // generates len(b) random bytes
	for i := 0; i < length; i++ {
		b[i] = chars[int(b[i])%ll]
	}
	return string(b)
}
