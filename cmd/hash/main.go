// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/alecthomas/kong"
)

func newKong(extra ...kong.Option) (*kong.Kong, error) {
	return kong.New(
		new(CLI),
		append(
			[]kong.Option{
				kong.UsageOnError(),
				kong.Description("hashes plaintext using bascule's infrastructure"),
			},
			extra...,
		)...,
	)
}

func run(args []string, extra ...kong.Option) {
	var ctx *kong.Context
	k, err := newKong(extra...)
	if err == nil {
		ctx, err = k.Parse(args)
	}

	if err == nil {
		err = ctx.Run()
	}

	k.FatalIfErrorf(err)
}

func main() {
	run(os.Args[1:])
}
