package acquire

import (
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

//RemoteBearerTokenAcquirer implements Acquirer and fetches the tokens from a remote location with caching strategy
type RemoteBearerTokenAcquirer struct {
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

// NewRemoteBearerTokenAcquirer returns a RemoteBearerTokenAcquirer configured with the given options
func NewRemoteBearerTokenAcquirer(options RemoteBearerTokenAcquirerOptions) (*RemoteBearerTokenAcquirer, error) {
	if options.GetToken == nil {
		options.GetToken = DefaultTokenParser
	}

	if options.GetExpiration == nil {
		options.GetExpiration = DefaultExpirationParser
	}

	//TODO: we should inject timeout and buffer defaults values as well

	return &RemoteBearerTokenAcquirer{
		options:             options,
		authValueExpiration: time.Now(),
		httpClient: &http.Client{
			Timeout: options.Timeout,
		},
		nonExpiringSpecialCase: time.Unix(0, 0),
	}, nil
}

func (acquirer *RemoteBearerTokenAcquirer) Acquire() (string, error) {
	if time.Now().Add(acquirer.options.Buffer).Before(acquirer.authValueExpiration) {
		return acquirer.authValue, nil
	}

	req, err := http.NewRequest("GET", acquirer.options.AuthURL, nil)
	if err != nil {
		return "", emperror.Wrap(err, "failed to create new request for Bearer")
	}

	for key, value := range acquirer.options.RequestHeaders {
		req.Header.Set(key, value)
	}

	resp, errHTTP := acquirer.httpClient.Do(req)
	if errHTTP != nil {
		return "", emperror.Wrapf(errHTTP, "error making request to '%v' to acquire bearer token", acquirer.options.AuthURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non 200 code acquiring Bearer: code %v", resp.Status)
	}

	respBody, errRead := ioutil.ReadAll(resp.Body)
	if errRead != nil {
		return "", emperror.Wrap(errRead, "error reading HTTP response body")
	}

	token, err := acquirer.options.GetToken(respBody)
	if err != nil {
		return "", emperror.Wrap(err, "error parsing bearer token from http response body")
	}
	expiration, err := acquirer.options.GetExpiration(respBody)
	if err != nil {
		return "", emperror.Wrap(err, "error parsing bearer token expiration from http response body")
	}

	acquirer.authValue, acquirer.authValueExpiration = "Bearer "+token, expiration
	return acquirer.authValue, nil
}
