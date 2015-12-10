package token_fetcher

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	trace "github.com/cloudfoundry-incubator/trace-logger"
	"github.com/pivotal-golang/clock"
)

type OAuthConfig struct {
	TokenEndpoint string `yaml:"token_endpoint"`
	ClientName    string `yaml:"client_name"`
	ClientSecret  string `yaml:"client_secret"`
	Port          int    `yaml:"port"`
}

type TokenFetcherConfig struct {
	MaxNumberOfRetries   uint32
	RetryInterval        time.Duration
	ExpirationBufferTime int64
}

type TokenFetcher interface {
	FetchToken(useCachedToken bool) (*Token, error)
}

type Token struct {
	AccessToken string `json:"access_token"`
	// Expire time in seconds
	ExpireTime int64 `json:"expires_in"`
}

type Fetcher struct {
	clock              clock.Clock
	config             *OAuthConfig
	client             *http.Client
	tokenFetcherConfig TokenFetcherConfig
	cachedToken        *Token
	refetchTokenTime   int64
	lock               *sync.Mutex
}

func NewTokenFetcher(config *OAuthConfig, tokenFetcherConfig TokenFetcherConfig, clock clock.Clock) (TokenFetcher, error) {
	if config == nil {
		return nil, errors.New("OAuth configuration cannot be nil")
	}

	if config.Port <= 0 || config.Port > 65535 {
		return nil, errors.New("OAuth port is not in valid range 1-65535")
	}

	if config.ClientName == "" {
		return nil, errors.New("OAuth Client ID cannot be empty")
	}

	if config.ClientSecret == "" {
		return nil, errors.New("OAuth Client Secret cannot be empty")
	}

	if config.TokenEndpoint == "" {
		return nil, errors.New("OAuth Token endpoint cannot be empty")
	}

	if tokenFetcherConfig.MaxNumberOfRetries == 0 {
		return nil, errors.New("Max number of retries cannot be zero")
	}

	if tokenFetcherConfig.ExpirationBufferTime < 0 {
		return nil, errors.New("Expiration buffer time cannot be negative")
	}

	return &Fetcher{
		config:             config,
		client:             &http.Client{},
		tokenFetcherConfig: tokenFetcherConfig,
		clock:              clock,
		lock:               new(sync.Mutex),
	}, nil
}

func (f *Fetcher) FetchToken(useCachedToken bool) (*Token, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if useCachedToken && f.canReturnCachedToken() {
		return f.cachedToken, nil
	}

	retry := true
	var retryCount uint32 = 1
	var token *Token
	for retry == true {
		fmt.Println("Calling doFetch")
		token, retry, err := f.doFetch()
		fmt.Printf("RETRY:%t, RETRY COUNT:%d\n", retry, retryCount)
		if token != nil {
			break
		}
		if retry && retryCount < f.tokenFetcherConfig.MaxNumberOfRetries {
			fmt.Printf("SLEEPING BEFORE RETRYING...\n")
			retryCount++
			f.clock.Sleep(f.tokenFetcherConfig.RetryInterval)
			fmt.Printf("WOKE UP...\n")
			continue
		} else {
			return nil, err
		}
	}

	f.updateCachedToken(token)
	return token, nil
}

func (f *Fetcher) doFetch() (*Token, bool, error) {
	values := url.Values{}
	values.Add("grant_type", "client_credentials")
	requestBody := values.Encode()
	tokenURL := fmt.Sprintf("%s:%d/oauth/token", f.config.TokenEndpoint, f.config.Port)
	request, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer([]byte(requestBody)))
	if err != nil {
		return nil, false, err
	}

	request.SetBasicAuth(f.config.ClientName, f.config.ClientSecret)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	request.Header.Add("Accept", "application/json; charset=utf-8")
	trace.DumpRequest(request)
	fmt.Println("Calling http client do")
	resp, err := f.client.Do(request)
	if err != nil {
		fmt.Printf("Error from oauth server:%#v\n", err)
		return nil, true, err
	}
	fmt.Println("Done calling oauth server")
	defer resp.Body.Close()

	trace.DumpResponse(resp)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, true, err
	}

	if resp.StatusCode != http.StatusOK {
		retry := false
		fmt.Printf("Status Code:%d\n", resp.StatusCode)
		if resp.StatusCode >= http.StatusInternalServerError {
			retry = true
		}
		fmt.Printf("Retry:%t\n", retry)
		return nil, retry, errors.New(fmt.Sprintf("status code: %d, body: %s", resp.StatusCode, body))
	}

	token := &Token{}
	err = json.Unmarshal(body, token)
	if err != nil {
		return nil, false, err
	}
	return token, false, nil
}

func (f *Fetcher) canReturnCachedToken() bool {
	return f.cachedToken != nil && f.clock.Now().Unix() < f.refetchTokenTime
}

func (f *Fetcher) updateCachedToken(token *Token) {
	f.cachedToken = token
	f.refetchTokenTime = f.clock.Now().Unix() + (token.ExpireTime - f.tokenFetcherConfig.ExpirationBufferTime)
}
