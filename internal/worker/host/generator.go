// Package host generates the host:ip string for actual transport connection to worker.
// it has three main ways to provide host:ip string:
// scanner: it launches a scanner and saves the suitable ip:port combinations in a queue.
// the queue has a fixed size that is defined in config. each queue expires after a while.
// the expiry time is defined in config but its default value is 30 minutes. this means that
// every 30 minutes, a new scanner is launched and after that, the old queue will be discarded.
// when a worker wants to connect to a host, it pops an ip from the queue joins it with a random
// port and returns it to the worker. the list of possible ports is defined in config.
// shuffler: user will provide a list of hosts in config. the shuffler will shuffle the list
// and return's a random host:port combination shuffler will accept ips and cidrs.
package host
