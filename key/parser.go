package key

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	ErrorPEMRequired                 = errors.New("Keys must be PEM-encoded")
	ErrorUnsupportedPrivateKeyFormat = errors.New("Private keys must be in PKCS1 or PKCS8 format")
	ErrorNotRSAPrivateKey            = errors.New("Only RSA private keys are supported")
	ErrorNotRSAPublicKey             = errors.New("Only RSA public keys or certificates are suppored")
)

// Parser parses a chunk of bytes into a Pair.  Parser implementations must
// always be safe for concurrent access.
type Parser interface {
	// Parse examines data to produce a Pair.  If the returned error is not nil,
	// the Pair will always be nil.  This method is responsible for dealing with
	// any required decoding, such as PEM or DER.
	ParseKey(context.Context, Purpose, []byte) (Pair, error)
}

// defaultParser is the internal default Parser implementation
type defaultParser struct{}

func (p defaultParser) String() string {
	return "defaultParser"
}

func (p defaultParser) parseRSAPrivateKey(ctx context.Context, purpose Purpose, decoded []byte) (Pair, error) {
	var (
		parsedKey interface{}
		err       error
	)

	if parsedKey, err = x509.ParsePKCS1PrivateKey(decoded); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(decoded); err != nil {
			return nil, ErrorUnsupportedPrivateKeyFormat
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrorNotRSAPrivateKey
	}

	return &rsaPair{
		purpose: purpose,
		public:  privateKey.Public(),
		private: privateKey,
	}, nil
}

func (p defaultParser) parseRSAPublicKey(ctx context.Context, purpose Purpose, decoded []byte) (Pair, error) {
	var (
		parsedKey interface{}
		err       error
	)

	if parsedKey, err = x509.ParsePKIXPublicKey(decoded); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrorNotRSAPublicKey
	}

	return &rsaPair{
		purpose: purpose,
		public:  publicKey,
		private: nil,
	}, nil
}

func (p defaultParser) ParseKey(ctx context.Context, purpose Purpose, data []byte) (Pair, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrorPEMRequired
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if purpose.RequiresPrivateKey() {
		return p.parseRSAPrivateKey(ctx, purpose, block.Bytes)
	} else {
		return p.parseRSAPublicKey(ctx, purpose, block.Bytes)
	}
}

// DefaultParser is the global, singleton default parser.  All keys submitted to
// this parser must be PEM-encoded.
var DefaultParser Parser = defaultParser{}
