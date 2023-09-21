package resolvers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/uoosef/bepass/config"
	"github.com/uoosef/bepass/internal/dialer"
	"github.com/uoosef/bepass/internal/logger"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

// DOHResolver represents the config options for setting up a DOH based resolver.
type DOHResolver struct {
	client          *http.Client
	server          string
	resolverOptions Options
}

// NewDOHResolver accepts a nameserver address and configures a DOH based resolver.
func NewDOHResolver(server string, resolverOpts Options) (Resolver, error) {
	// do basic validation
	u, err := url.ParseRequestURI(server)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid HTTPS nameserver", server)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("missing https in %s", server)
	}
	httpClient := dialer.MakeHTTPClient(config.Worker.Enable, resolverOpts.Timeout)
	return &DOHResolver{
		client:          httpClient,
		server:          server,
		resolverOptions: resolverOpts,
	}, nil
}

// Lookup takes a dns.Question and sends them to DNS Server.
// It parses the Response from the server in a custom output format.
func (r *DOHResolver) Lookup(question dns.Question) (Response, error) {
	var (
		rsp      Response
		messages = PrepareMessages(question, r.resolverOptions.Ndots, r.resolverOptions.SearchList)
	)

	for _, msg := range messages {
		logger.Infof("attempting to resolve %s, ns: %s, ndots: %s",
			msg.Question[0].Name,
			r.server,
			r.resolverOptions.Ndots,
		)
		// get the DNS Message in wire format.
		b, err := msg.Pack()
		if err != nil {
			return rsp, err
		}
		now := time.Now()
		// Make an HTTP POST request to the DNS server with the DNS message as wire format bytes in the body.
		resp, err := r.client.Post(r.server, "application/dns-message", bytes.NewBuffer(b))
		if err != nil {
			return rsp, err
		}
		if resp.StatusCode == http.StatusMethodNotAllowed {
			targetUrl, err := url.Parse(r.server)
			if err != nil {
				return rsp, err
			}
			targetUrl.RawQuery = fmt.Sprintf("dns=%v", base64.RawURLEncoding.EncodeToString(b))
			resp, err = r.client.Get(targetUrl.String())
			if err != nil {
				return rsp, err
			}
		}
		if resp.StatusCode != http.StatusOK {
			return rsp, fmt.Errorf("error from nameserver %s", resp.Status)
		}
		rtt := time.Since(now)
		// extract the binary response in DNS Message.
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return rsp, err
		}

		err = msg.Unpack(body)
		if err != nil {
			return rsp, err
		}
		// pack questions in output.
		for _, q := range msg.Question {
			ques := Question{
				Name:  q.Name,
				Class: dns.ClassToString[q.Qclass],
				Type:  dns.TypeToString[q.Qtype],
			}
			rsp.Questions = append(rsp.Questions, ques)
		}
		// get the authorities and answers.
		output := ParseMessage(&msg, rtt, r.server)
		rsp.Authorities = output.Authorities
		rsp.Answers = output.Answers

		if len(output.Answers) > 0 {
			// stop iterating the searchlist.
			break
		}
	}
	return rsp, nil
}
