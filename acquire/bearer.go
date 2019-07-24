package acquire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/goph/emperror"
)

//TokenParser defines the function signature of a bearer token extractor from a payload
type TokenParser func([]byte) (string, error)

//ParseExpiration defines the function signature of a bearer token expiration date extractor
type ParseExpiration func([]byte) (time.Time, error)

//DefaultTokenParser extracts a bearer token as defined by a SimpleBearer in a payload
func DefaultTokenParser(data []byte) (string, error) {
	var bearer SimpleBearer

	if errUnmarshal := json.Unmarshal(data, &bearer); errUnmarshal != nil {
		return "", emperror.Wrap(errUnmarshal, "unable to parse bearer token")
	}
	return bearer.Token, nil
}

//DefaultExpirationParser extracts a bearer token expiration date as defined by a SimpleBearer in a payload
func DefaultExpirationParser(data []byte) (time.Time, error) {
	var bearer SimpleBearer

	if errUnmarshal := json.Unmarshal(data, &bearer); errUnmarshal != nil {
		return time.Time{}, emperror.Wrap(errUnmarshal, "unable to parse bearer token expiration")
	}
	return time.Now().Add(time.Duration(bearer.Expiration) * time.Second), nil
}

//RemoteBearerTokenAcquirerOptions provides configuration for the RemoteBearerTokenAcquirer
type RemoteBearerTokenAcquirerOptions struct {
	AuthURL        string            `json:"authURL"`
	Timeout        time.Duration     `json:"timeout"`
	Buffer         time.Duration     `json:"buffer"`
	RequestHeaders map[string]string `json:"requestHeaders"`

	GetToken      TokenParser
	GetExpiration ParseExpiration
}

type remoteBearerTokenAcquirer struct {
	options RemoteBearerTokenAcquirerOptions

	cachedAuth string
	expires    time.Time
}

//SimpleBearer defines the field name mappings used by the default Token and Expiration parsers
type SimpleBearer struct {
	Expiration float64 `json:"expires_in"`
	Token      string  `json:"serviceAccessToken"`
}

//NewFixedBearerTokenAcquirer returns an acquirer which returns an authorization
//string value of the form 'Bearer [input-token]'
func NewFixedBearerTokenAcquirer(token string) Acquirer {
	return &fixedValueAcquirer{Auth: "Bearer " + token}
}

//NewRemoteBearerTokenAcquirer returns an acquirer which fetches tokens from a configurable URL location
//The acquirer caches tokens and only re-fetches them from such URL once they have expired
func NewRemoteBearerTokenAcquirer(options RemoteBearerTokenAcquirerOptions) Acquirer {
	if options.GetToken == nil {
		options.GetToken = DefaultTokenParser
	}

	if options.GetExpiration == nil {
		options.GetExpiration = DefaultExpirationParser
	}

	//TODO: we should inject defaults values for the other options as well

	return &remoteBearerTokenAcquirer{
		options: options,
		expires: time.Now(),
	}
}

func (acquire *remoteBearerTokenAcquirer) Acquire() (string, error) {
	//TODO: Are we treating time.Unix(0, 0) as the "never expired" case here?
	if time.Now().Add(acquire.options.Buffer).Before(acquire.expires) || acquire.expires == time.Unix(0, 0) {
		return acquire.cachedAuth, nil
	}

	req, err := http.NewRequest("GET", acquire.options.AuthURL, bytes.NewBufferString("{}"))
	if err != nil {
		return "", emperror.Wrap(err, "failed to create new request for Bearer")
	}

	for key, value := range acquire.options.RequestHeaders {
		req.Header.Set(key, value)
	}

	httpclient := &http.Client{
		Timeout: acquire.options.Timeout,
	}

	resp, errHTTP := httpclient.Do(req)
	if errHTTP != nil {
		return "", fmt.Errorf("error acquiring Bearer token: [%s]", errHTTP.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non 200 code acquiring Bearer: code %v", resp.Status)
	}

	respBody, errRead := ioutil.ReadAll(resp.Body)
	if errRead != nil {
		return "", fmt.Errorf("error reading Bearer token: [%s]", errRead.Error())
	}

	token, err := acquire.options.GetToken(respBody)
	if err != nil {
		return "", fmt.Errorf("error parsing Bearer token: [%s]", err.Error())
	}
	expires, err := acquire.options.GetExpiration(respBody)
	if err != nil {
		return "", fmt.Errorf("error parsing Bearer token: [%s]", err.Error())
	}

	acquire.cachedAuth, acquire.expires = "Bearer "+token, expires
	return acquire.cachedAuth, nil
}
