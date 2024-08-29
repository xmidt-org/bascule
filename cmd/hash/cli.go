// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/xmidt-org/bascule/basculehash"
	"golang.org/x/crypto/bcrypt"
)

const (
	// MaxBcryptPlaintextLength is the maximum length of the input that
	// bcrypt will operate on.  This value isn't exposed via the
	// golang.org/x/crypto/bcrypt package.
	MaxBcryptPlaintextLength = 72
)

// Bcrypt is the subcommand for the bcrypt algorithm.
type Bcrypt struct {
	Cost      int    `default:"10" short:"c" help:"the cost parameter for bcrypt.  Must be between 4 and 31, inclusive."`
	Plaintext string `arg:"" required:"" help:"the plaintext (e.g. password) to hash.  This cannot exceed 72 bytes in length."`
}

func (cmd *Bcrypt) Validate() error {
	switch {
	case cmd.Cost < bcrypt.MinCost:
		return fmt.Errorf("Cost cannot be less than %d", bcrypt.MinCost)

	case cmd.Cost > bcrypt.MaxCost:
		return fmt.Errorf("Cost cannot be greater than %d", bcrypt.MaxCost)

	case len(cmd.Plaintext) > MaxBcryptPlaintextLength:
		return fmt.Errorf("Plaintext length cannot exceed %d bytes", MaxBcryptPlaintextLength)

	default:
		return nil
	}
}

func (cmd *Bcrypt) Run(kong *kong.Kong) error {
	hasher := basculehash.Bcrypt{
		Cost: cmd.Cost,
	}

	_, err := hasher.Hash(kong.Stdout, []byte(cmd.Plaintext))
	return err
}

// CLI is the top grammar node for the command-line tool.
type CLI struct {
	// Bcrypt is the bcrypt subcommand.  This is the only supported hash
	// algorithm right now.
	Bcrypt Bcrypt `cmd:""`
}
