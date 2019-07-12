# basculehttp

The package for auth related middleware, implemented as [alice-style http decorators](https://github.com/justinas/alice).

[![GoDoc](https://godoc.org/github.com/xmidt-org/bascule/basculehttp?status.svg)](https://godoc.org/github.com/xmidt-org/bascule/basculehttp)

## Summary

This package makes it easy to validate the Authorization of an incoming http 
request.

## Decorators

This packages has three http decorators (which act as middleware):

1. **Constructor**: Parses the Authorization header into a Token and runs some 
   basic validation using a TokenFactory.  The basic validation varies and is 
   determined by the TokenFactory.  Basic and JWT TokenFactories are included 
   in the package, but the consumer can also create its own TokenFactory.  
   After the Token is created, it is added to the request context.
2. **Enforcer**: Gets the Token from the request context and then validates 
   that the Token is authorized using validator functions provided by the 
   consumer.
3. **Listener**: Gets the Token from the request context and then provides it 
   to a function set by the consumer and called by the decorator.  Some 
   examples of using the Listener is to log a statement related to the Token 
   found, or to add to some metrics based on something in the Token.