// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/alecthomas/kong"
)

func newKong() (*kong.Kong, error) {
	return kong.New(
		new(CLI),
		kong.UsageOnError(),
		kong.Description("hashes plaintext using bascule's infrastructure"),
	)
}

func run(grammar *kong.Kong, args []string) (err error) {
	var ctx *kong.Context
	if err == nil {
		ctx, err = grammar.Parse(args)
	}

	if err == nil {
		err = ctx.Run()
	}

	return
}

func main() {
	grammar, err := newKong()
	if err == nil {
		err = run(grammar, os.Args[1:])
	}

	grammar.FatalIfErrorf(err)
}
