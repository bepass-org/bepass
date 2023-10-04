// Package socks5 provides functionality for defining and managing custom rules
// that determine whether specific actions are allowed or prohibited by a SOCKS5
// proxy server. These rules can be used to filter and control various command types.
package socks5

import (
	"context"

	"github.com/bepass-org/bepass/socks5/statute"
)

// RuleSet is an interface used to provide custom rules for allowing or prohibiting actions.
type RuleSet interface {
	Allow(ctx context.Context, req *Request) (context.Context, bool)
}

// PermitCommand is an implementation of the RuleSet interface, enabling filtering
// of supported commands.
type PermitCommand struct {
	EnableConnect   bool
	EnableBind      bool
	EnableAssociate bool
}

// NewPermitNone returns a RuleSet that disallows all types of internet actions.
func NewPermitNone() RuleSet {
	return &PermitCommand{false, false, false}
}

// NewPermitAll returns a RuleSet that allows all types of internet actions.
func NewPermitAll() RuleSet {
	return &PermitCommand{true, true, true}
}

// NewPermitConnAndAss returns a RuleSet that allows Connect and Associate connections.
func NewPermitConnAndAss() RuleSet {
	return &PermitCommand{true, false, true}
}

// Allow implements the RuleSet interface.
func (p *PermitCommand) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	switch req.Command {
	case statute.CommandConnect:
		return ctx, p.EnableConnect
	case statute.CommandBind:
		return ctx, p.EnableBind
	case statute.CommandAssociate:
		return ctx, p.EnableAssociate
	}
	return ctx, false
}
