package bascule

import "strings"

type Error struct {
	Operation string
	Cause     error
	Reason    string
}

func (e *Error) Unwrap() error {
	return e.Cause
}

func (e *Error) Error() string {
	var o strings.Builder
	o.WriteString(e.Operation)
	o.WriteString(" error: ")
	o.WriteString(e.Reason)

	return o.String()
}
