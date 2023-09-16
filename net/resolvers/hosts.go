// Package resolve provides DNS resolution and host file management functionality.
package resolvers

// CheckHosts checks if a given domain exists in the local resolver's hosts file
// and returns the corresponding IP address if found, or an empty string if not.
func (lr *LocalResolver) CheckHosts(domain string) string {
	for h := range lr.Hosts {
		if lr.Hosts[h].Domain == domain {
			return lr.Hosts[h].IP
		}
	}
	return ""
}
