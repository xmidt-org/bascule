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
	return time.Now().Add(time.Duration(bearer.ExpiresInSeconds) * time.Second), nil
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
	options                RemoteBearerTokenAcquirerOptions
	authValue              string
	authValueExpiration    time.Time
	httpClient             *http.Client
	nonExpiringSpecialCase time.Time
}

//SimpleBearer defines the field name mappings used by the default bearer token and expiration parsers
type SimpleBearer struct {
	ExpiresInSeconds float64 `json:"expires_in"`
	Token            string  `json:"serviceAccessToken"`
}

//NewRemoteBearerTokenAcquirer returns an acquirerr which fetches tokens from a configurable URL location
//The acquirerr caches tokens and only re-fetches them from such URL once they have expired
//Note: If you'd like for a token to never expire, set is expiration to time.Unix(0,0)
func NewRemoteBearerTokenAcquirer(options RemoteBearerTokenAcquirerOptions) (Acquirer, error) {
	if options.GetToken == nil {
		options.GetToken = DefaultTokenParser
	}

	if options.GetExpiration == nil {
		options.GetExpiration = DefaultExpirationParser
	}

	//TODO: we should inject defaults values for the other options as well

	return &remoteBearerTokenAcquirer{
		options:             options,
		authValueExpiration: time.Now(),
		httpClient: &http.Client{
			Timeout: options.Timeout,
		},
		nonExpiringSpecialCase: time.Unix(0, 0),
	}, nil
}

func (acquirer *remoteBearerTokenAcquirer) Acquire() (string, error) {
	unexpiredAuthValue := time.Now().Add(acquirer.options.Buffer).Before(acquirer.authValueExpiration)
	if unexpiredAuthValue || acquirer.authValueExpiration == acquirer.nonExpiringSpecialCase {
		return acquirer.authValue, nil
	}

	req, err := http.NewRequest("GET", acquirer.options.AuthURL, bytes.NewBufferString("{}"))
	if err != nil {
		return "", emperror.Wrap(err, "failed to create new request for Bearer")
	}

	for key, value := range acquirer.options.RequestHeaders {
		req.Header.Set(key, value)
	}

	resp, errHTTP := acquirer.httpClient.Do(req)
	if errHTTP != nil {
		return "", fmt.Errorf("error acquiring bearer token: [%s]", errHTTP.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non 200 code acquiring Bearer: code %v", resp.Status)
	}

	respBody, errRead := ioutil.ReadAll(resp.Body)
	if errRead != nil {
		return "", fmt.Errorf("error reading Bearer token: [%s]", errRead.Error())
	}

	token, err := acquirer.options.GetToken(respBody)
	if err != nil {
		return "", fmt.Errorf("error parsing Bearer token: [%s]", err.Error())
	}
	expiration, err := acquirer.options.GetExpiration(respBody)
	if err != nil {
		return "", fmt.Errorf("error parsing Bearer token: [%s]", err.Error())
	}

	acquirer.authValue, acquirer.authValueExpiration = "Bearer "+token, expiration
	return acquirer.authValue, nil
}
