package basculehttp

import (
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/xmidt-org/bascule/redesign/bascule"
)

type basicToken struct {
	user     string
	password string
}

func (bt basicToken) Type() string      { return "Basic" }
func (bt basicToken) Principal() string { return bt.user }

type jwtToken struct {
	principal string
}

func (jt jwtToken) Type() string      { return "Bearer" }
func (jt jwtToken) Principal() string { return jt.principal }

type TokenParser struct {
}

func (tp *TokenParser) parseBasic(serialized string) (bt basicToken, err error) {
	var decoded []byte
	decoded, err = base64.StdEncoding.DecodeString(serialized)
	if err == nil {
		if pos := bytes.IndexByte(decoded, ':'); pos > 0 {
			bt.user = string(decoded[0:pos])
			bt.password = string(decoded[pos+1:])
		} else {
			err = &bascule.Error{
				Operation: "ParseToken",
				Reason:    "invalid basic auth token",
			}
		}
	}

	return
}

func (tp *TokenParser) ParseToken(authorization string) (t bascule.Token, err error) {
	tokenType, serialized, valid := strings.Cut(authorization, " ")
	if !valid {
		err = &bascule.Error{
			Operation: "ParseToken",
			Reason:    "invalid authorization",
		}
	}

	if err == nil {
		switch tokenType {
		case "Basic":
			t, err = tp.parseBasic(serialized)

		case "Bearer":
		default:

		}
	}

	return
}
