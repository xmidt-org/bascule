// package bascule provides a token interface and basic implementation, which
// can be validated and added and taken from a context.  Some basic checks
// which can be used to validate are also provided.
package bascule

import (
	"time"

	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

//Attributes is the interface that wraps methods which dictate how to interact
//with a token's attributes. Getter functions return a boolean as second element
//which indicates that a value of the requested type exists at the given key path.
//Key path separators are configurable through AttributeOptions
type Attributes interface {
	Get(key string) (interface{}, bool)
	GetBool(key string) (bool, bool)
	GetDuration(key string) (time.Duration, bool)
	GetFloat64(key string) (float64, bool)
	GetInt64(key string) (int64, bool)
	GetIntSlice(key string) ([]int, bool)
	GetString(key string) (string, bool)
	GetStringMap(key string) (map[string]interface{}, bool)
	GetStringSlice(key string) ([]string, bool)
	GetTime(key string) (time.Time, bool)
	IsSet(key string) bool
	FullView() map[string]interface{}
}

var nilTime = time.Time{}

//AttributesOptions allows customizing Attributes initialization
type AttributesOptions struct {
	//KeyDelimiter configures the separator for building key paths
	//for the Attributes getter functions. Defaults to '.'
	KeyDelimiter string

	//AttributesMap is used as the initial attributes datasource
	AttributesMap map[string]interface{}
}

type attributes struct {
	v *viper.Viper

	//Note: having m is superfluous given v. However, it's a caching
	//optimization for FullView() since v.AllSettings() is a relatively
	//expensive operation
	m map[string]interface{}
}

func (a *attributes) Get(key string) (interface{}, bool) {
	if !a.v.IsSet(key) {
		return nil, false
	}

	return a.v.Get(key), true
}

func (a *attributes) GetBool(key string) (bool, bool) {
	if !a.v.IsSet(key) {
		return false, false
	}
	v, err := cast.ToBoolE(a.v.Get(key))
	if err != nil {
		return false, false
	}
	return v, true
}

func (a *attributes) GetDuration(key string) (time.Duration, bool) {
	if !a.v.IsSet(key) {
		return 0, false
	}
	v, err := cast.ToDurationE(a.v.Get(key))
	if err != nil {
		return 0, false
	}

	return v, true
}
func (a *attributes) GetFloat64(key string) (float64, bool) {
	if !a.v.IsSet(key) {
		return 0, false
	}
	v, err := cast.ToFloat64E(a.v.Get(key))
	if err != nil {
		return 0, false
	}

	return v, true
}

func (a *attributes) GetInt64(key string) (int64, bool) {
	if !a.v.IsSet(key) {
		return 0, false
	}
	v, err := cast.ToInt64E(a.v.Get(key))
	if err != nil {
		return 0, false
	}
	return v, true
}

func (a *attributes) GetIntSlice(key string) ([]int, bool) {
	if !a.v.IsSet(key) {
		return nil, false
	}
	v, err := cast.ToIntSliceE(a.v.Get(key))
	if err != nil {
		return nil, false
	}
	return v, true

}
func (a *attributes) GetString(key string) (string, bool) {
	if !a.v.IsSet(key) {
		return "", false
	}
	v, err := cast.ToStringE(a.v.Get(key))
	if err != nil {
		return "", false
	}
	return v, true
}
func (a *attributes) GetStringMap(key string) (map[string]interface{}, bool) {
	if !a.v.IsSet(key) {
		return nil, false
	}
	v, err := cast.ToStringMapE(a.v.Get(key))
	if err != nil {
		return nil, false
	}
	return v, true

}
func (a *attributes) GetStringSlice(key string) ([]string, bool) {
	if !a.v.IsSet(key) {
		return nil, false
	}
	v, err := cast.ToStringSliceE(a.v.Get(key))
	if err != nil {
		return nil, false
	}
	return v, true
}

func (a *attributes) GetTime(key string) (time.Time, bool) {
	if !a.v.IsSet(key) {
		return nilTime, false
	}
	v, err := cast.ToTimeE(a.v.Get(key))
	if err != nil {
		return nilTime, false
	}
	return v, true
}

func (a *attributes) IsSet(key string) bool {
	return a.v.IsSet(key)
}

func (a *attributes) FullView() map[string]interface{} {
	return a.m
}

//NewAttributes builds an empty Attributes instance.
func NewAttributes() Attributes {
	return NewAttributesWithOptions(AttributesOptions{})
}

//NewAttributesFromMap builds an Attributes instance with
//the given map as datasource. Default AttributeOptions are used.
func NewAttributesFromMap(m map[string]interface{}) Attributes {
	return NewAttributesWithOptions(AttributesOptions{
		AttributesMap: m,
	})
}

//NewAttributesWithOptions builds an Attributes instance from the given
//options. Zero value options are ok.
func NewAttributesWithOptions(o AttributesOptions) Attributes {
	var (
		options []viper.Option
		v       *viper.Viper
	)

	if o.KeyDelimiter != "" {
		options = append(options, viper.KeyDelimiter(o.KeyDelimiter))
	}

	v = viper.NewWithOptions(options...)

	v.MergeConfigMap(o.AttributesMap)

	return &attributes{
		v: v,
		m: o.AttributesMap,
	}
}

// Token is the behavior supplied by all secure tokens
type Token interface {
	// Type is the custom token type assigned by plugin code
	Type() string

	// Principal is the security principal, e.g. the user name or client id
	Principal() string

	// Attributes are an arbitrary set of name/value pairs associated with the token.
	// Typically, these will be filled with information supplied by the user, e.g. the claims of a JWT.
	Attributes() Attributes
}

// simpleToken is a very basic token type that can serve as the Token for many types of secure pipelines
type simpleToken struct {
	tokenType  string
	principal  string
	attributes Attributes
}

func (st simpleToken) Type() string {
	return st.tokenType
}

func (st simpleToken) Principal() string {
	return st.principal
}

func (st simpleToken) Attributes() Attributes {
	return st.attributes
}

// NewToken creates a Token from basic information.  Many secure pipelines can use the returned value as
// their token.  Specialized pipelines can create additional interfaces and augment the returned Token
// as desired.  Alternatively, some pipelines can simply create their own Tokens out of whole cloth.
func NewToken(tokenType, principal string, attributes Attributes) Token {
	return simpleToken{tokenType, principal, attributes}
}
