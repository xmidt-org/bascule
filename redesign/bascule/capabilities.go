package bascule

// Capabilities is an optional interface that a Token can implement
// to supply security capabilities.
type Capabilities interface {
	// Capabilities returns the slice of security operations this
	// Token is allowed to be used with.
	Capabilities() []string
}

// GetCapabilities returns the set of security capabilities associated
// with the given Token.  If the Token implements Capabilities, that
// interface is consulted.  Otherwise, this function returns an
// empty slice.
func GetCapabilities(t Token) (caps []string) {
	if c, ok := t.(Capabilities); ok {
		caps = c.Capabilities()
	}

	return
}
