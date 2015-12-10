package token_fetcher_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/cloudfoundry-incubator/uaa-token-fetcher"
	"github.com/pivotal-golang/clock/fakeclock"

	"bytes"

	trace "github.com/cloudfoundry-incubator/trace-logger"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var verifyBody = func(expectedBody string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		Expect(err).ToNot(HaveOccurred())

		defer r.Body.Close()
		Expect(string(body)).To(Equal(expectedBody))
	}
}

var _ = Describe("TokenFetcher", func() {
	const (
		DefaultMaxNumberOfRetries   = 3
		DefaultRetryInterval        = 15 * time.Second
		DefaultExpirationBufferTime = 30
	)

	var (
		cfg                *OAuthConfig
		server             *ghttp.Server
		clock              *fakeclock.FakeClock
		tokenFetcherConfig TokenFetcherConfig
		canUseCachedToken  bool
	)

	BeforeEach(func() {
		canUseCachedToken = true
		cfg = &OAuthConfig{}
		server = ghttp.NewServer()

		url, err := url.Parse(server.URL())
		Expect(err).ToNot(HaveOccurred())

		addr := strings.Split(url.Host, ":")

		cfg.TokenEndpoint = "http://" + addr[0]
		cfg.Port, err = strconv.Atoi(addr[1])
		Expect(err).ToNot(HaveOccurred())

		cfg.ClientName = "client-name"
		cfg.ClientSecret = "client-secret"
		clock = fakeclock.NewFakeClock(time.Now())
		tokenFetcherConfig = TokenFetcherConfig{
			MaxNumberOfRetries:   DefaultMaxNumberOfRetries,
			RetryInterval:        DefaultRetryInterval,
			ExpirationBufferTime: DefaultExpirationBufferTime,
		}
	})

	AfterEach(func() {
		server.Close()
	})

	verifyLogs := func(stdout *bytes.Buffer, reqMessage, resMessage string) {
		r, err := ioutil.ReadAll(stdout)
		log := string(r)
		Expect(err).NotTo(HaveOccurred())
		Expect(log).To(ContainSubstring("REQUEST: "))
		Expect(log).To(ContainSubstring(reqMessage))

		Expect(log).To(ContainSubstring("RESPONSE: "))
		Expect(log).To(ContainSubstring(resMessage))
	}

	getOauthHandlerFunc := func(status int, token *Token) http.HandlerFunc {
		return ghttp.CombineHandlers(
			ghttp.VerifyRequest("POST", "/oauth/token"),
			ghttp.VerifyBasicAuth("client-name", "client-secret"),
			ghttp.VerifyContentType("application/x-www-form-urlencoded; charset=UTF-8"),
			ghttp.VerifyHeader(http.Header{
				"Accept": []string{"application/json; charset=utf-8"},
			}),
			verifyBody("grant_type=client_credentials"),
			ghttp.RespondWithJSONEncoded(status, token),
		)
	}

	verifyFetchWithRetries := func(fetcher TokenFetcher, stdout *bytes.Buffer, server *ghttp.Server, expectedResponses ...string) {
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer GinkgoRecover()
			defer wg.Done()
			_, err := fetcher.FetchToken(canUseCachedToken)
			Expect(err).To(HaveOccurred())
		}(&wg)

		for i := 0; i < DefaultMaxNumberOfRetries; i++ {
			fmt.Printf("Trying %d times\n", i)
			Eventually(server.ReceivedRequests, 5*time.Second, 1*time.Second).Should(HaveLen(i + 1))
			clock.Increment(DefaultRetryInterval + 10*time.Second)
		}

		r, err := ioutil.ReadAll(stdout)
		Expect(err).NotTo(HaveOccurred())
		log := string(r)

		for _, respMessage := range expectedResponses {
			Expect(log).To(ContainSubstring(respMessage))
		}

		wg.Wait()
	}
	Describe("NewTokenFetcher", func() {
		Context("when all values are valid", func() {
			It("returns a token fetcher instance", func() {
				tokenFetcher, err := NewTokenFetcher(cfg, tokenFetcherConfig, clock)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokenFetcher).NotTo(BeNil())
			})
		})

		Context("when values are invalid", func() {
			Context("when oauth config is nil", func() {
				It("returns error", func() {
					tokenFetcher, err := NewTokenFetcher(nil, tokenFetcherConfig, clock)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("OAuth configuration cannot be nil"))
					Expect(tokenFetcher).To(BeNil())
				})
			})

			Context("when oauth config port is not in range", func() {
				It("returns error", func() {
					oauthConfig := &OAuthConfig{
						TokenEndpoint: "http://some.url",
						ClientName:    "client-name",
						ClientSecret:  "client-secret",
						Port:          -1,
					}
					tokenFetcher, err := NewTokenFetcher(oauthConfig, tokenFetcherConfig, clock)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("OAuth port is not in valid range 1-65535"))
					Expect(tokenFetcher).To(BeNil())
				})
			})

			Context("when oauth config client id is empty", func() {
				It("returns error", func() {
					oauthConfig := &OAuthConfig{
						TokenEndpoint: "http://some.url",
						ClientName:    "",
						ClientSecret:  "client-secret",
						Port:          8080,
					}
					tokenFetcher, err := NewTokenFetcher(oauthConfig, tokenFetcherConfig, clock)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("OAuth Client ID cannot be empty"))
					Expect(tokenFetcher).To(BeNil())
				})
			})

			Context("when oauth config client secret is empty", func() {
				It("returns error", func() {
					oauthConfig := &OAuthConfig{
						TokenEndpoint: "http://some.url",
						ClientName:    "client-name",
						ClientSecret:  "",
						Port:          8080,
					}
					tokenFetcher, err := NewTokenFetcher(oauthConfig, tokenFetcherConfig, clock)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("OAuth Client Secret cannot be empty"))
					Expect(tokenFetcher).To(BeNil())
				})
			})

			Context("when oauth config tokenendpoint is empty", func() {
				It("returns error", func() {
					oauthConfig := &OAuthConfig{
						TokenEndpoint: "",
						ClientName:    "client-name",
						ClientSecret:  "client-secret",
						Port:          8080,
					}
					tokenFetcher, err := NewTokenFetcher(oauthConfig, tokenFetcherConfig, clock)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("OAuth Token endpoint cannot be empty"))
					Expect(tokenFetcher).To(BeNil())
				})
			})

			Context("when token fetcher config's max number of retries is zero", func() {
				It("returns error", func() {
					tokenFetcherCfg := TokenFetcherConfig{
						MaxNumberOfRetries:   0,
						RetryInterval:        2 * time.Second,
						ExpirationBufferTime: 30,
					}
					tokenFetcher, err := NewTokenFetcher(cfg, tokenFetcherCfg, clock)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("Max number of retries cannot be zero"))
					Expect(tokenFetcher).To(BeNil())
				})
			})

			Context("when token fetcher config's expiration buffer time is negative", func() {
				It("returns error", func() {
					tokenFetcherCfg := TokenFetcherConfig{
						MaxNumberOfRetries:   3,
						RetryInterval:        2 * time.Second,
						ExpirationBufferTime: -1,
					}
					tokenFetcher, err := NewTokenFetcher(cfg, tokenFetcherCfg, clock)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("Expiration buffer time cannot be negative"))
					Expect(tokenFetcher).To(BeNil())
				})
			})
		})
	})

	Describe("FetchToken", func() {
		var (
			tokenFetcher TokenFetcher
		)

		BeforeEach(func() {
			var err error
			tokenFetcher, err = NewTokenFetcher(cfg, tokenFetcherConfig, clock)
			Expect(err).NotTo(HaveOccurred())
			Expect(tokenFetcher).NotTo(BeNil())
		})

		Context("multiple retries", func() {
			Context("when OAuth server cannot be reached", func() {
				It("returns an error", func() {
					stdout := bytes.NewBuffer([]byte{})
					trace.SetStdout(stdout)
					trace.NewLogger("true")

					cfg.TokenEndpoint = "http://bogus.url"
					fetcher, err := NewTokenFetcher(cfg, tokenFetcherConfig, clock)
					Expect(err).NotTo(HaveOccurred())
					wg := sync.WaitGroup{}
					wg.Add(1)
					go func(wg *sync.WaitGroup) {
						defer GinkgoRecover()
						defer wg.Done()
						_, err := fetcher.FetchToken(canUseCachedToken)
						Expect(err).To(HaveOccurred())
					}(&wg)

					for i := 0; i < DefaultMaxNumberOfRetries; i++ {
						fmt.Printf("Trying %d times\n", i)
						Eventually(func() string {
							r, err := ioutil.ReadAll(stdout)
							log := string(r)
							if err != nil {
								return err.Error()
							}
							fmt.Println("printing log...", log)
							fmt.Printf("Contains request:%t\n", strings.Contains(log, "REQUEST:"))
							if !strings.Contains(log, "REQUEST:") {
								return "No Request in log"
							}
							fmt.Printf("Contains POST:%t\n", strings.Contains(log, "POST /oauth/token HTTP/1.1"))
							if !strings.Contains(log, "POST /oauth/token HTTP/1.1") {
								return "No POST message in log"
							}
							fmt.Printf("ALL SUCCESS\n")

							return ""
						}, 5*time.Second, 1*time.Second).Should(Equal(""))

						clock.Increment(DefaultRetryInterval + 10*time.Second)
					}
					wg.Wait()
				})
			})

			Context("when OAuth server returns a 5xx http status code", func() {
				BeforeEach(func() {
					server.AppendHandlers(
						getOauthHandlerFunc(http.StatusServiceUnavailable, nil),
						getOauthHandlerFunc(http.StatusInternalServerError, nil),
						getOauthHandlerFunc(http.StatusBadGateway, nil),
					)
				})

				It("retries a number of times", func() {
					stdout := bytes.NewBuffer([]byte{})
					trace.SetStdout(stdout)
					trace.NewLogger("true")

					fetcher, err := NewTokenFetcher(cfg, tokenFetcherConfig, clock)
					Expect(err).NotTo(HaveOccurred())
					verifyFetchWithRetries(fetcher, stdout, server, "HTTP/1.1 503", "HTTP/1.1 500", "HTTP/1.1 502")
				})
			})

			Context("when OAuth server returns a 4xx http status code", func() {
				It("does not retry", func() {

				})
			})

		})

		Context("when a new token needs to be fetched from OAuth server", func() {
			Context("when the respose body is malformed", func() {
				It("returns an error", func() {
					stdout := bytes.NewBuffer([]byte{})
					trace.SetStdout(stdout)
					trace.NewLogger("true")

					server.AppendHandlers(
						ghttp.RespondWithJSONEncoded(http.StatusOK, "broken garbage response"),
					)

					fetcher, err := NewTokenFetcher(cfg, tokenFetcherConfig, clock)
					Expect(err).NotTo(HaveOccurred())
					_, err = fetcher.FetchToken(canUseCachedToken)
					Expect(err).To(HaveOccurred())
					Expect(server.ReceivedRequests()).Should(HaveLen(1))

					verifyLogs(stdout, "POST /oauth/token HTTP/1.1", "HTTP/1.1 200 OK")
				})
			})

			Context("when a non 200 OK is returned", func() {
				It("returns an error", func() {
					stdout := bytes.NewBuffer([]byte{})
					trace.SetStdout(stdout)
					trace.NewLogger("true")

					server.AppendHandlers(
						ghttp.RespondWith(http.StatusBadRequest, "you messed up"),
					)

					fetcher, err := NewTokenFetcher(cfg, tokenFetcherConfig, clock)
					Expect(err).NotTo(HaveOccurred())
					_, err = fetcher.FetchToken(canUseCachedToken)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal("status code: 400, body: you messed up"))
					Expect(server.ReceivedRequests()).Should(HaveLen(1))
					verifyLogs(stdout, "POST /oauth/token HTTP/1.1", "HTTP/1.1 400 Bad Request")
				})
			})

			Context("when there is no cached token", func() {
				It("returns a new token and logs request response", func() {
					responseBody := &Token{
						AccessToken: "the token",
						ExpireTime:  20,
					}

					server.AppendHandlers(
						getOauthHandlerFunc(http.StatusOK, responseBody),
					)

					token, err := tokenFetcher.FetchToken(canUseCachedToken)
					Expect(err).NotTo(HaveOccurred())
					Expect(server.ReceivedRequests()).Should(HaveLen(1))
					Expect(token.AccessToken).To(Equal("the token"))
					Expect(token.ExpireTime).To(Equal(int64(20)))
				})

				Context("when multiple goroutines fetch a token", func() {
					It("contacts oauth server only once and returns cached token", func() {
						responseBody := &Token{
							AccessToken: "the token",
							ExpireTime:  3600,
						}

						server.AppendHandlers(
							getOauthHandlerFunc(http.StatusOK, responseBody),
						)
						wg := sync.WaitGroup{}
						for i := 0; i < 2; i++ {
							wg.Add(1)
							go func(wg *sync.WaitGroup) {
								defer GinkgoRecover()
								defer wg.Done()
								token, err := tokenFetcher.FetchToken(canUseCachedToken)
								Expect(err).NotTo(HaveOccurred())
								Expect(server.ReceivedRequests()).Should(HaveLen(1))
								Expect(token.AccessToken).To(Equal("the token"))
								Expect(token.ExpireTime).To(Equal(int64(3600)))
							}(&wg)
						}
						wg.Wait()
					})
				})
			})

			Context("when cached token is expired", func() {
				It("returns a new token and logs request response", func() {
					firstResponseBody := &Token{
						AccessToken: "the token",
						ExpireTime:  3600,
					}
					secondResponseBody := &Token{
						AccessToken: "another token",
						ExpireTime:  3600,
					}

					server.AppendHandlers(
						getOauthHandlerFunc(http.StatusOK, firstResponseBody),
						getOauthHandlerFunc(http.StatusOK, secondResponseBody),
					)

					token, err := tokenFetcher.FetchToken(canUseCachedToken)
					Expect(err).NotTo(HaveOccurred())
					Expect(server.ReceivedRequests()).Should(HaveLen(1))
					Expect(token.AccessToken).To(Equal("the token"))
					Expect(token.ExpireTime).To(Equal(int64(3600)))
					clock.Increment((3600 - DefaultExpirationBufferTime) * time.Second)

					token, err = tokenFetcher.FetchToken(canUseCachedToken)
					Expect(err).NotTo(HaveOccurred())
					Expect(server.ReceivedRequests()).Should(HaveLen(2))
					Expect(token.AccessToken).To(Equal("another token"))
					Expect(token.ExpireTime).To(Equal(int64(3600)))
				})
			})
		})

		Context("when non expired token is cached", func() {
			Context("when a cached token can be used", func() {
				It("returns the cached token", func() {
					firstResponseBody := &Token{
						AccessToken: "the token",
						ExpireTime:  3600,
					}
					secondResponseBody := &Token{
						AccessToken: "another token",
						ExpireTime:  3600,
					}

					server.AppendHandlers(
						getOauthHandlerFunc(http.StatusOK, firstResponseBody),
						getOauthHandlerFunc(http.StatusOK, secondResponseBody),
					)

					token, err := tokenFetcher.FetchToken(canUseCachedToken)
					Expect(err).NotTo(HaveOccurred())
					Expect(server.ReceivedRequests()).Should(HaveLen(1))
					Expect(token.AccessToken).To(Equal("the token"))
					Expect(token.ExpireTime).To(Equal(int64(3600)))
					clock.Increment(3000 * time.Second)

					token, err = tokenFetcher.FetchToken(canUseCachedToken)
					Expect(err).NotTo(HaveOccurred())
					Expect(server.ReceivedRequests()).Should(HaveLen(1))
					Expect(token.AccessToken).To(Equal("the token"))
					Expect(token.ExpireTime).To(Equal(int64(3600)))
				})
			})

			Context("when a cached token cannot be used", func() {
				It("returns a new token", func() {
					firstResponseBody := &Token{
						AccessToken: "the token",
						ExpireTime:  3600,
					}
					secondResponseBody := &Token{
						AccessToken: "another token",
						ExpireTime:  3600,
					}

					server.AppendHandlers(
						getOauthHandlerFunc(http.StatusOK, firstResponseBody),
						getOauthHandlerFunc(http.StatusOK, secondResponseBody),
					)

					token, err := tokenFetcher.FetchToken(canUseCachedToken)
					Expect(err).NotTo(HaveOccurred())
					Expect(server.ReceivedRequests()).Should(HaveLen(1))
					Expect(token.AccessToken).To(Equal("the token"))
					Expect(token.ExpireTime).To(Equal(int64(3600)))

					token, err = tokenFetcher.FetchToken(false)
					Expect(err).NotTo(HaveOccurred())
					Expect(server.ReceivedRequests()).Should(HaveLen(2))
					Expect(token.AccessToken).To(Equal("another token"))
					Expect(token.ExpireTime).To(Equal(int64(3600)))
				})
			})

		})
	})
})
