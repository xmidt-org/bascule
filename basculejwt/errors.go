// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculejwt

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/xmidt-org/bascule"
)

// The errors a TokenParser returns, describing why a JWT was rejected.
//
// This package exists so that a caller does not have to know which JWT library
// produced a failure.  These errors serve the same purpose: a caller can tell
// an expired token from an unverifiable one with errors.Is, without importing
// jwx.  The underlying jwx error is wrapped rather than replaced, so a caller
// that does want it can still reach it.
//
// A returned error is joined with every one of these that applies, together
// with one of this module's general errors, so a caller may ask a coarse
// question or a precise one:
//
//	errors.Is(err, bascule.ErrBadCredentials)  // was the token rejected at all?
//	errors.Is(err, basculejwt.ErrInvalidClaims) // was a claim the problem?
//	errors.Is(err, basculejwt.ErrNotYetValid)  // which claim, exactly?
//
// An expired token is all three: it is a bad credential, its claims are
// invalid, and specifically it has expired.  Nothing has to choose which of
// those to report.
//
// A token that could not be read at all is joined with
// bascule.ErrInvalidCredentials; one that was read but not accepted is joined
// with bascule.ErrBadCredentials.
//
// A note on key retrieval.
//
// Nothing in this package, and nothing in the JWT library beneath it, can tell
// you why a key was not usable.  A token bearing a key id that was never issued
// and a key store that is unreachable arrive here as the same failure, and both
// are reported as ErrInvalidSignature.  That is not a gap to be closed by
// matching more carefully on what comes back: the distinction does not survive
// the trip.
//
// It matters because the two want opposite responses, and guessing wrong is
// costly either way: mistake an outage for unknown key ids and it hides behind
// ordinary rejections, mistake unknown key ids for an outage and anyone can
// manufacture one by sending a made up key id.
//
// The key provider is the only thing that knows which it is looking at, and
// even it cannot always say from a single lookup -- a cold cache after an
// outage and an unknown key id look alike from there too.  So a deployment that
// needs to tell them apart should take that signal from its key provider
// directly: clortho, for instance, reports its own failures and can say whether
// its key ring is being refreshed successfully.  Judge the health of key
// retrieval from the key provider, and judge tokens from the errors here.
//
// The provider's error is joined into what this package returns, so a caller
// may still reach it with errors.Is.  Reaching it is fine.  Concluding from
// this package's errors alone that key retrieval failed is not.
var (
	// ErrExpired indicates the token's exp claim is in the past.
	ErrExpired = errors.New("token expired")

	// ErrNotYetValid indicates the token's nbf claim is in the future.
	ErrNotYetValid = errors.New("token not yet valid")

	// ErrInvalidIssuedAt indicates the token's iat claim is not acceptable.
	ErrInvalidIssuedAt = errors.New("invalid issued at time")

	// ErrInvalidIssuer indicates the token's iss claim is not accepted.
	ErrInvalidIssuer = errors.New("issuer not accepted")

	// ErrInvalidAudience indicates the token's aud claim is not accepted.
	ErrInvalidAudience = errors.New("audience not accepted")

	// ErrMissingClaim indicates a required claim was absent.
	ErrMissingClaim = errors.New("required claim missing")

	// ErrInvalidClaims indicates a claim was rejected.  It accompanies the more
	// specific errors above where one applies, so that a caller may count claim
	// failures as a whole without enumerating them.
	ErrInvalidClaims = errors.New("claims invalid")

	// ErrInvalidSignature indicates the signature could not be verified.
	//
	// This covers every reason a key did not produce a verified signature,
	// including not obtaining a key at all.  Do not read anything further into
	// it, and in particular do not try to infer from it whether key retrieval
	// failed.  See the note on key retrieval accompanying these errors.
	ErrInvalidSignature = errors.New("signature not verified")

	// ErrMalformed indicates the value itself was the problem: parsing failed,
	// and neither the claims nor the signature were the cause, so nothing
	// could be read from it.
	ErrMalformed = errors.New("malformed token")
)

// errTable maps a jwx failure to this package's error for it.  Every entry that
// matches is reported, so an expired token is both ErrInvalidClaims and
// ErrExpired and nothing has to decide between them.
//
// This is a slice rather than a map only so that a joined error's message comes
// out the same every time.  jwt.ParseError is deliberately absent: it is true
// of every failure from jwt.Parse, so it classifies nothing.
var errTable = []struct {
	jwx      error
	specific error
}{
	{jwt.TokenExpiredError{}, ErrExpired},
	{jwt.TokenNotYetValidError{}, ErrNotYetValid},
	{jwt.InvalidIssuedAtError{}, ErrInvalidIssuedAt},
	{jwt.InvalidIssuerError{}, ErrInvalidIssuer},
	{jwt.InvalidAudienceError{}, ErrInvalidAudience},
	{jwt.MissingRequiredClaimError{}, ErrMissingClaim},
	{jwt.ValidationError{}, ErrInvalidClaims},
	{jws.VerifyError(), ErrInvalidSignature},
}

// translate pairs a jwx parse failure with this package's errors for it: every
// specific error that applies, and the general error describing the kind of
// failure.  The jwx error is joined as well, so a caller that wants what
// actually happened -- or an error from its own key provider -- can still reach
// it.
//
// Order is not significant.  Every entry that matches is reported, rather than
// the first, so a failure that is several things at once is reported as all of
// them.  A failure that came from somewhere other than jwt.Parse is returned
// unchanged, since this package has nothing to say about it.
func translate(err error) error {
	if err == nil {
		return nil
	}

	// The check was abandoned before it reached a verdict, so there is nothing
	// to report about the token.  Returning the failure unchanged says that,
	// where joining a credential error would claim the token was examined and
	// found wanting.
	//
	// This is checked first because jwx wraps the context error in a verify
	// error, which the table below would otherwise match.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	var errs []error
	for _, entry := range errTable {
		if errors.Is(err, entry.jwx) {
			errs = append(errs, entry.specific)
		}
	}

	if len(errs) > 0 {
		errs = append(errs, bascule.ErrBadCredentials)
	} else {
		// nothing above explains the failure.  If it came from jwt.Parse at
		// all, the value itself is what could not be read; anything else is
		// not ours to describe.
		if !errors.Is(err, jwt.ParseError{}) {
			return err
		}

		errs = append(errs, bascule.ErrInvalidCredentials, ErrMalformed)
	}

	return errors.Join(append(errs, err)...)
}
