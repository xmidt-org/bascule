package basculehttp

import (
	"net/http"
	"strings"

	"github.com/xmidt-org/bascule/redesign/bascule"
)

const DefaultAuthorizationHeader = "Authorization"

// Accessor is the strategy for extracting the raw, serialized token
// from an HTTP request.
type Accessor interface {
	GetToken(*http.Request) (string, error)
}

var defaultAccessor Accessor = AuthorizationAccessor{}

// AuthorizationAccessor is an Accessor that pulls the serialized token
// from an HTTP header of the format defined by https://www.rfc-editor.org/rfc/rfc7235#section-4.2.
// Only the single header is considered.
type AuthorizationAccessor struct {
	// Header is the name of the Authorization header.  If unset, then
	// DefaultAuthorizationHeader is used.
	Header string
}

func (aa AuthorizationAccessor) header() string {
	if len(aa.Header) == 0 {
		return DefaultAuthorizationHeader
	}

	return aa.Header
}

func (aa AuthorizationAccessor) GetToken(r *http.Request) (serialized string, err error) {
	header := aa.header()
	serialized = r.Header.Get(header)

	if len(serialized) == 0 {
		var reason strings.Builder
		reason.WriteString("no token found in header ")
		reason.WriteString(header)
		err = &bascule.Error{
			Operation: "TokenAccess",
			Reason:    reason.String(),
		}
	}

	return
}