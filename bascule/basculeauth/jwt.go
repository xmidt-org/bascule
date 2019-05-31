package basculeauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/goph/emperror"
	"io/ioutil"
	"net/http"
	"time"
)

type ParseToken func([]byte) (string, error)

func DefaultTokenParser(data []byte) (string, error) {
	var jwt JWTBasic

	if errUnmarshal := json.Unmarshal(data, &jwt); errUnmarshal != nil {
		return "", emperror.Wrap(errUnmarshal, "unable to read json")
	}
	return jwt.Token, nil
}

type ParseExpiration func([]byte) (time.Time, error)

func DefaultExpirationParser(data []byte) (time.Time, error) {
	var jwt JWTBasic

	if errUnmarshal := json.Unmarshal(data, &jwt); errUnmarshal != nil {
		return time.Time{}, emperror.Wrap(errUnmarshal, "unable to read json")
	}
	return time.Now().Add(time.Duration(jwt.Expiration) * time.Second), nil
}

type JWTAcquirer struct {
	AuthURL        string            `json:"authURL"`
	Timeout        time.Duration     `json:"timeout"`
	Buffer         time.Duration     `json:"buffer"`
	RequestHeaders map[string]string `json:"requestHeaders"`

	GetToken      ParseToken
	GetExpiration ParseExpiration

	cachedAuth string
	expires    time.Time
}

type JWTBasic struct {
	Expiration float64 `json:"expires_in"`
	Token      string  `json:"serviceAccessToken"`
}

func (acquire *JWTAcquirer) SetDefaults() {
	acquire.GetToken = DefaultTokenParser
	acquire.GetExpiration = DefaultExpirationParser
}

func (acquire *JWTAcquirer) Acquire() (string, error) {
	if time.Now().Add(acquire.Buffer).Before(acquire.expires) {
		return acquire.cachedAuth, nil
	}

	jsonStr := []byte(`{}`)
	httpclient := &http.Client{
		Timeout: acquire.Timeout,
	}
	req, err := http.NewRequest("GET", acquire.AuthURL, bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", emperror.Wrap(err, "failed to create new request for JWT")
	}

	for key, value := range acquire.RequestHeaders {
		req.Header.Set(key, value)
	}

	resp, errHTTP := httpclient.Do(req)
	if errHTTP != nil {
		return "", fmt.Errorf("error acquiring JWT token: [%s]", errHTTP.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non 200 code acquiring JWT: code %v", resp.Status)
	}

	respBody, errRead := ioutil.ReadAll(resp.Body)
	if errRead != nil {
		return "", fmt.Errorf("error reading JWT token: [%s]", errRead.Error())
	}

	auth, err := acquire.GetToken(respBody)
	if err != nil {
		return "", fmt.Errorf("error parsing JWT token: [%s]", err.Error())
	}
	expires, err := acquire.GetExpiration(respBody)
	if err != nil {
		return "", fmt.Errorf("error parsing JWT token: [%s]", err.Error())
	}

	acquire.cachedAuth = fmt.Sprintf("Bearer %s", auth)
	acquire.expires = expires
	return acquire.cachedAuth, nil
}
