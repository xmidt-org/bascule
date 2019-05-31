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

type JWTAcquirer struct {
	Client  string        `json:"client"`
	Secret  string        `json:"secret"`
	AuthURL string        `json:"authURL"`
	Timeout time.Duration `json:"timeout"`
	Buffer  time.Duration `json:"buffer"`

	cachedAuth string
	expires    time.Time
}

type JWTToken struct {
	Expiration float64 `json:"expires_in"`
	Token      string  `json:"serviceAccessToken"`
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
	req.Header.Set("X-Client-Id", acquire.Client)
	req.Header.Set("X-Client-Secret", acquire.Secret)

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

	var jwt JWTToken

	if errUnmarshal := json.Unmarshal(respBody, &jwt); errUnmarshal != nil {
		return "", emperror.Wrap(errUnmarshal, "unable to read json in JWT response")
	}
	acquire.cachedAuth = fmt.Sprintf("Bearer %s", jwt.Token)
	acquire.expires = time.Now().Add(time.Duration(jwt.Expiration) * time.Second)
	return acquire.cachedAuth, nil
}
