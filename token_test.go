package bascule

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var attrs = NewAttributesFromMap(map[string]interface{}{"testkey": "testval", "attr": 5})

const (
	boolGetter = iota
	durationGetter
	float64Getter
	int64Getter
	intSliceGetter
	stringGetter
	stringMapGetter
	stringSliceGetter
	timeGetter
)

func TestToken(t *testing.T) {
	assert := assert.New(t)
	tokenType := "test type"
	principal := "test principal"
	token := NewToken(tokenType, principal, attrs)
	assert.Equal(tokenType, token.Type())
	assert.Equal(principal, token.Principal())
	assert.Equal(attrs, token.Attributes())
}

func TestGet(t *testing.T) {
	assert := assert.New(t)
	attributes := Attributes(attrs)

	val, ok := attributes.Get("testkey")
	assert.Equal("testval", val)
	assert.True(ok)

	val, ok = attributes.Get("noval")
	assert.Empty(val)
	assert.False(ok)

	emptyAttributes := NewAttributes()
	val, ok = emptyAttributes.Get("test")
	assert.Nil(val)
	assert.False(ok)
}

func TestTypedGetters(t *testing.T) {
	testCases := []struct {
		typeEnum int
		name     string
		key      string
		v        interface{}
	}{
		{
			typeEnum: boolGetter,
			name:     "getBool",
			v:        true,
		},

		{
			typeEnum: durationGetter,
			name:     "getDuration",
			v:        time.Second * 1,
		},

		{
			typeEnum: float64Getter,
			name:     "getFloat64",
			v:        3.14,
		},
		{
			typeEnum: int64Getter,
			name:     "getInt64",
			v:        int64(1 << 40),
		},
		{
			typeEnum: intSliceGetter,
			name:     "getIntSlice",
			v:        []int{1, 2},
		},

		{
			typeEnum: stringGetter,
			name:     "getString",
			v:        "string",
		},

		{
			typeEnum: stringMapGetter,
			name:     "getStringMap",
			v:        map[string]interface{}{"string": "map"},
		},

		{
			typeEnum: stringSliceGetter,
			name:     "getStringSlice",
			v:        []string{"string", "slice"},
		},

		{
			typeEnum: timeGetter,
			name:     "getTime",
			v:        time.Now(),
		},
	}

	var (
		sep         = ">"
		topKey      = "nested"
		notFoundKey = "notfound"
		badTypeKey  = "noneOfTheAboveType"

		topKeyMap = make(map[string]interface{})

		m = map[string]interface{}{
			badTypeKey: struct{}{},
			topKey:     topKeyMap,
		}
	)

	//sync test cases and attributes
	for i, testCase := range testCases {
		topKeyMap[testCase.name] = testCase.v
		testCases[i].key = fmt.Sprintf("%s%s%s", topKey, sep, testCase.name)
	}

	a := NewAttributesWithOptions(AttributesOptions{
		KeyDelimiter:  sep,
		AttributesMap: m,
	})

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert := assert.New(t)
			switch testCase.typeEnum {
			case boolGetter:
				_, okNotFound := a.GetBool(notFoundKey)
				_, okBadType := a.GetBool(badTypeKey)
				fmt.Println(testCase.key)
				v, okValid := a.GetBool(testCase.key)
				assertAll(assert, assertData{okNotFound, okBadType, okValid, testCase.v, v})
			case durationGetter:
				_, okNotFound := a.GetDuration(notFoundKey)
				_, okBadType := a.GetDuration(badTypeKey)
				v, okValid := a.GetDuration(testCase.key)
				assertAll(assert, assertData{okNotFound, okBadType, okValid, testCase.v, v})
			case float64Getter:
				_, okNotFound := a.GetFloat64(notFoundKey)
				_, okBadType := a.GetFloat64(badTypeKey)
				v, okValid := a.GetFloat64(testCase.key)
				assertAll(assert, assertData{okNotFound, okBadType, okValid, testCase.v, v})
			case int64Getter:
				_, okNotFound := a.GetInt64(notFoundKey)
				_, okBadType := a.GetInt64(badTypeKey)
				v, okValid := a.GetInt64(testCase.key)
				assertAll(assert, assertData{okNotFound, okBadType, okValid, testCase.v, v})
			case intSliceGetter:
				_, okNotFound := a.GetIntSlice(notFoundKey)
				_, okBadType := a.GetIntSlice(badTypeKey)
				v, okValid := a.GetIntSlice(testCase.key)
				assertAll(assert, assertData{okNotFound, okBadType, okValid, testCase.v, v})
			case stringGetter:
				_, okNotFound := a.GetString(notFoundKey)
				_, okBadType := a.GetString(badTypeKey)
				v, okValid := a.GetString(testCase.key)
				assertAll(assert, assertData{okNotFound, okBadType, okValid, testCase.v, v})
			case stringMapGetter:
				_, okNotFound := a.GetStringMap(notFoundKey)
				_, okBadType := a.GetStringMap(badTypeKey)
				v, okValid := a.GetStringMap(testCase.key)
				assertAll(assert, assertData{okNotFound, okBadType, okValid, testCase.v, v})
			case stringSliceGetter:
				_, okNotFound := a.GetStringSlice(notFoundKey)
				_, okBadType := a.GetStringSlice(badTypeKey)
				v, okValid := a.GetStringSlice(testCase.key)
				assertAll(assert, assertData{okNotFound, okBadType, okValid, testCase.v, v})
			case timeGetter:
				_, okNotFound := a.GetTime(notFoundKey)
				_, okBadType := a.GetTime(badTypeKey)
				v, okValid := a.GetTime(testCase.key)
				assertAll(assert, assertData{okNotFound, okBadType, okValid, testCase.v, v})
			}
		})
	}
}

func TestFullView(t *testing.T) {
	m := map[string]interface{}{"k0": 0, "k1": 1}
	a := NewAttributesFromMap(m)
	assert := assert.New(t)
	assert.Equal(m, a.FullView())
}

type assertData struct {
	okNotFound bool
	okBadType  bool
	okValid    bool
	expected   interface{}
	actual     interface{}
}

func assertAll(a *assert.Assertions, d assertData) {
	a.False(d.okNotFound)
	a.False(d.okBadType)
	a.True(d.okValid)
	a.Equal(d.expected, d.actual)
}
