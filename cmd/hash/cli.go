package main

import (
	"fmt"
	"io"

	"github.com/xmidt-org/bascule/basculehash"
	"golang.org/x/crypto/bcrypt"
)

// Context is the contextual information for all commands.
type Context struct {
	Stdout io.Writer
	Stderr io.Writer
}

// Bcrypt is the subcommand for the bcrypt algorithm.
type Bcrypt struct {
	Cost      int    `default:"10" help:"the cost parameter for bcrypt"`
	Plaintext string `arg:"" required:""`
}

func (cmd *Bcrypt) Validate() error {
	switch {
	case cmd.Cost < bcrypt.MinCost:
		return fmt.Errorf("Cost cannot be less than %d", bcrypt.MinCost)

	case cmd.Cost > bcrypt.MaxCost:
		return fmt.Errorf("Cost cannot be greater than %d", bcrypt.MaxCost)

	default:
		return nil
	}
}

func (cmd *Bcrypt) Run(ctx *Context) error {
	hasher := basculehash.Bcrypt{
		Cost: cmd.Cost,
	}

	_, err := hasher.Hash(ctx.Stdout, []byte(cmd.Plaintext))
	return err
}

// CLI is the top grammar node for the command-line tool.
type CLI struct {
	// Bcrypt is the bcrypt subcommand.  This is the only supported hash
	// algorithm right now.
	Bcrypt Bcrypt `cmd:""`
}
