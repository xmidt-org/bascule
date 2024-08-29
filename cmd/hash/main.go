// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
)

func run(args []string, ctx *Context) (err error) {
	var (
		grammar *kong.Kong
		kongCtx *kong.Context
	)

	grammar, err = kong.New(new(CLI), kong.Bind(ctx))
	if err == nil {
		kongCtx, err = grammar.Parse(args)
	}

	if err == nil {
		err = kongCtx.Run()
	}

	return
}

func main() {
	err := run(os.Args[1:], &Context{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	})

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
