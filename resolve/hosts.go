package resolve

func (lr *LocalResolver) CheckHosts(domain string) string {
	for h := range lr.Hosts {
		if lr.Hosts[h].Domain == domain {
			return lr.Hosts[h].IP
		}
	}
	return ""
}
