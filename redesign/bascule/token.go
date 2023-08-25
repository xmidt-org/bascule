package bascule

// Token represents everything known about the subject of a secure operation.
// The actual concrete type of Token will depend on the infrastructure used.
type Token interface {
	// Type refers to how this Token was instantiated.
	Type() string

	// Principal identifies actual entity that wants to perform
	// the operation for which this Token was presented.
	Principal() string
}

// TokenParser is the strategy for turning a serialized form of a token
// into a Token object.
type TokenParser[T Token] interface {
	ParseToken(serialized string) (T, error)
}
