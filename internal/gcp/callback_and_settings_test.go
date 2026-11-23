// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/httpc"
	oauth "github.com/oakwood-commons/oauth-helpers"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func clearAmbientGCPEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvGoogleApplicationCredentials, "")
	t.Setenv(EnvGoogleExternalAccount, "")
	t.Setenv(EnvCloudSDKConfig, t.TempDir())
	metaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not gce", http.StatusNotFound)
	}))
	t.Cleanup(metaSrv.Close)
	t.Setenv(EnvGCEMetadataHost, metaSrv.Listener.Addr().String())
}

func makeTestIDToken(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("sig"))
}

func jsonHTTPResponse(status int, payload any) *http.Response {
	b, _ := json.Marshal(payload)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

func configureCustomCallbackPages(t *testing.T, p *Plugin) (string, string) {
	t.Helper()
	successDoc := "<!doctype html><html><body>GCP-BLUEPRINT-SUCCESS</body></html>"
	failureDoc := "<!doctype html><html><body>GCP-BLUEPRINT-FAILURE</body></html>"
	pages := &sdkplugin.AuthCallbackPages{
		SuccessHTML: []byte(successDoc),
		FailureHTML: []byte(failureDoc),
	}
	cfgCtx := sdkplugin.WithHostClient(context.Background(), p.cachedHostClient)
	mockHTTP := p.httpClient
	require.NoError(t, p.ConfigureAuthHandler(cfgCtx, HandlerName, sdkplugin.ProviderConfig{
		BinaryName:        "mycli",
		AuthCallbackPages: pages,
	}))
	if mockHTTP != nil {
		p.httpClient = mockHTTP
	}
	return successDoc, failureDoc
}

func completeLoopbackCallback(t *testing.T, authURL, code string) {
	t.Helper()
	u, err := url.Parse(authURL)
	if !assert.NoError(t, err) {
		return
	}
	redirect := u.Query().Get("redirect_uri")
	state := u.Query().Get("state")
	go func() {
		resp, getErr := http.Get(redirect + "/?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)) //nolint:noctx
		if getErr == nil {
			_ = resp.Body.Close()
		}
	}()
}

func startPluginAuthGRPCServer(t *testing.T, p *Plugin) proto.AuthHandlerServiceClient {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	proto.RegisterAuthHandlerServiceServer(srv, &sdkplugin.AuthHandlerGRPCServer{Impl: p})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop() })

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return proto.NewAuthHandlerServiceClient(conn)
}

type blockingHTTPClient struct {
	mu       sync.Mutex
	lastData url.Values
	onPost   func(ctx context.Context, endpoint string, data url.Values) (*http.Response, error)
}

func (b *blockingHTTPClient) PostForm(ctx context.Context, endpoint string, data url.Values) (*http.Response, error) {
	b.mu.Lock()
	b.lastData = data
	b.mu.Unlock()
	return b.onPost(ctx, endpoint, data)
}

func (b *blockingHTTPClient) Get(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
	return jsonHTTPResponse(http.StatusOK, map[string]any{"sub": "sub-1", "email": "user@example.com"}), nil
}

func (b *blockingHTTPClient) Do(_ context.Context, _ *http.Request) (*http.Response, error) {
	return jsonHTTPResponse(http.StatusInternalServerError, map[string]string{"error": "unexpected Do"}), nil
}

type capturingLogSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *capturingLogSink) Init(logr.RuntimeInfo) {}
func (s *capturingLogSink) Enabled(int) bool      { return true }
func (s *capturingLogSink) Info(_ int, msg string, keysAndValues ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprintf("%s %v", msg, keysAndValues))
}
func (s *capturingLogSink) Error(err error, msg string, keysAndValues ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprintf("%s: %v %v", msg, err, keysAndValues))
}
func (s *capturingLogSink) WithValues(...any) logr.LogSink { return s }
func (s *capturingLogSink) WithName(string) logr.LogSink   { return s }

func (s *capturingLogSink) Joined() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

func TestADCLogin_DeferredCompletionAndBlueprintCallbackPages(t *testing.T) {
	t.Run("withholds browser success page until token exchange, claim extraction, and credential storage complete", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		exchangeEntered := make(chan struct{})
		releaseExchange := make(chan struct{})

		validJWT := makeTestIDToken(map[string]any{
			"iss":   "https://accounts.google.com",
			"sub":   "gcp-sub-123",
			"email": "alice@example.com",
			"name":  "Alice Example",
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		p, _, _ := newTestPlugin(t)
		blocker := &blockingHTTPClient{
			onPost: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				close(exchangeEntered)
				<-releaseExchange
				return jsonHTTPResponse(http.StatusOK, TokenResponse{
					AccessToken:  "gcp-at",
					RefreshToken: "gcp-rt",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					IDToken:      validJWT,
				}), nil
			},
		}
		p.httpClient = blocker
		wantSuccess, _ := configureCustomCallbackPages(t, p)

		type browserOutcome struct {
			status int
			body   string
			csp    string
			err    error
		}
		browserCh := make(chan browserOutcome, 1)
		var capturedAuthURL string
		p.openBrowser = func(_ context.Context, authURL string) error {
			capturedAuthURL = authURL
			u, err := url.Parse(authURL)
			if err != nil {
				return err
			}
			redirectURI := u.Query().Get("redirect_uri")
			state := u.Query().Get("state")
			go func() {
				resp, getErr := http.Get(redirectURI + "/?code=GCP-CODE&state=" + url.QueryEscape(state)) //nolint:noctx
				if getErr != nil {
					browserCh <- browserOutcome{err: getErr}
					return
				}
				defer func() { _ = resp.Body.Close() }()
				b, readErr := io.ReadAll(resp.Body)
				browserCh <- browserOutcome{
					status: resp.StatusCode,
					body:   string(b),
					csp:    resp.Header.Get("Content-Security-Policy"),
					err:    readErr,
				}
			}()
			return nil
		}

		var prompts []sdkplugin.DeviceCodePrompt
		loginDone := make(chan error, 1)
		go func() {
			_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
				Flow: auth.FlowInteractive,
			}, func(prompt sdkplugin.DeviceCodePrompt) {
				prompts = append(prompts, prompt)
			})
			loginDone <- err
		}()

		<-exchangeEntered

		// While token exchange is blocked, browser response MUST remain held.
		select {
		case out := <-browserCh:
			t.Fatalf("browser received premature response before exchange/storage completed: %+v", out)
		case <-time.After(60 * time.Millisecond):
		}

		close(releaseExchange)
		require.NoError(t, <-loginDone)

		out := <-browserCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusOK, out.status)
		assert.Equal(t, wantSuccess, out.body)
		assert.Contains(t, out.csp, "default-src 'none'")
		require.Len(t, prompts, 1)
		assert.Equal(t, capturedAuthURL, prompts[0].VerificationURI)

		u, parseErr := url.Parse(capturedAuthURL)
		require.NoError(t, parseErr)
		blocker.mu.Lock()
		verifier := blocker.lastData.Get("code_verifier")
		blocker.mu.Unlock()
		assert.Equal(t, oauth.GenerateCodeChallenge(verifier), u.Query().Get("code_challenge"))
		assert.NotEmpty(t, u.Query().Get("state"))
	})

	t.Run("post-callback failures render 503 FailureHTML without leaking details or persisting partial credentials", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		validJWT := makeTestIDToken(map[string]any{
			"iss":   "https://accounts.google.com",
			"sub":   "gcp-sub-123",
			"email": "alice@example.com",
		})

		tests := []struct {
			name         string
			setup        func(p *Plugin, fake *fakeHostService, mockHTTP *MockHTTPClient)
			wantTermErr  string
			forbidInHTML string
		}{
			{
				name: "token exchange HTTP 400 failure",
				setup: func(_ *Plugin, _ *fakeHostService, mockHTTP *MockHTTPClient) {
					mockHTTP.AddResponse(http.StatusBadRequest, TokenErrorResponse{
						Error:            "invalid_grant",
						ErrorDescription: "gcp-secret-exchange-detail",
					})
				},
				wantTermErr:  "token exchange failed",
				forbidInHTML: "gcp-secret-exchange-detail",
			},
			{
				name: "token exchange network failure",
				setup: func(_ *Plugin, _ *fakeHostService, mockHTTP *MockHTTPClient) {
					mockHTTP.AddError(errors.New("dial tcp timeout internal-proxy"))
				},
				wantTermErr:  "token exchange failed",
				forbidInHTML: "internal-proxy",
			},
			{
				name: "token exchange truncated JSON on 200",
				setup: func(p *Plugin, _ *fakeHostService, _ *MockHTTPClient) {
					p.httpClient = &blockingHTTPClient{
						onPost: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
							return &http.Response{
								StatusCode: http.StatusOK,
								Body:       io.NopCloser(strings.NewReader(`{"access_token":"truncated`)),
							}, nil
						},
					}
				},
				wantTermErr:  "failed to parse token response",
				forbidInHTML: "truncated",
			},
			{
				name: "token exchange empty access_token on 200",
				setup: func(_ *Plugin, _ *fakeHostService, mockHTTP *MockHTTPClient) {
					mockHTTP.AddResponse(http.StatusOK, TokenResponse{})
				},
				wantTermErr:  "empty access_token",
				forbidInHTML: "empty access_token",
			},
			{
				name: "malformed ID token verification failure",
				setup: func(_ *Plugin, _ *fakeHostService, mockHTTP *MockHTTPClient) {
					mockHTTP.AddResponse(http.StatusOK, TokenResponse{
						AccessToken:  "at-secret-val",
						RefreshToken: "rt-secret-val",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						IDToken:      "not-a-valid-jwt",
					})
				},
				wantTermErr:  "failed to extract claims from ID token",
				forbidInHTML: "not-a-valid-jwt",
			},
			{
				name: "storeCredentials refresh token write failure",
				setup: func(_ *Plugin, fake *fakeHostService, mockHTTP *MockHTTPClient) {
					mockHTTP.AddResponse(http.StatusOK, TokenResponse{
						AccessToken:  "at-secret-val",
						RefreshToken: "rt-secret-val",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						IDToken:      validJWT,
					})
					fake.setSecretErr = errors.New("keyring locked")
				},
				wantTermErr:  "failed to store credentials",
				forbidInHTML: "keyring locked",
			},
			{
				name: "storeCredentials metadata write failure cleans up unreferenced refresh token",
				setup: func(_ *Plugin, fake *fakeHostService, mockHTTP *MockHTTPClient) {
					mockHTTP.AddResponse(http.StatusOK, TokenResponse{
						AccessToken:  "at-secret-val",
						RefreshToken: "rt-secret-val",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						IDToken:      validJWT,
					})
					fake.setSecretKeyErr = map[string]error{
						SecretKeyMetadata: errors.New("metadata store full"),
					}
				},
				wantTermErr:  "failed to store credentials",
				forbidInHTML: "metadata store full",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p, fake, mockHTTP := newTestPlugin(t)
				wantSuccess, wantFailure := configureCustomCallbackPages(t, p)
				tt.setup(p, fake, mockHTTP)

				type browserOutcome struct {
					status int
					body   string
					err    error
				}
				browserCh := make(chan browserOutcome, 1)
				p.openBrowser = func(_ context.Context, authURL string) error {
					u, parseErr := url.Parse(authURL)
					if parseErr != nil {
						return parseErr
					}
					redirectURI := u.Query().Get("redirect_uri")
					state := u.Query().Get("state")
					go func() {
						resp, getErr := http.Get(redirectURI + "/?code=ERR-CODE&state=" + url.QueryEscape(state)) //nolint:noctx
						if getErr != nil {
							browserCh <- browserOutcome{err: getErr}
							return
						}
						b, readErr := io.ReadAll(resp.Body)
						_ = resp.Body.Close()
						browserCh <- browserOutcome{status: resp.StatusCode, body: string(b), err: readErr}
					}()
					return nil
				}

				_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
					Flow: auth.FlowInteractive,
				}, nil)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantTermErr)
				assert.Empty(t, fake.secrets, "failed fresh login must not leave stored secrets")

				st, statusErr := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
				require.NoError(t, statusErr)
				assert.False(t, st.Authenticated)

				out := <-browserCh
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusServiceUnavailable, out.status)
				assert.Equal(t, wantFailure, out.body)
				assert.NotEqual(t, wantSuccess, out.body)
				assert.NotContains(t, out.body, tt.forbidInHTML)
			})
		}
	})

	t.Run("nil AuthCallbackPages serves safe 503 helper failure page and direct OAuth callback error drains 400 FailureHTML", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		// 1. Nil AuthCallbackPages (older host)
		pNil, _, mockHTTP := newTestPlugin(t)
		mockHTTP.AddResponse(http.StatusBadRequest, TokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "older-host-detail",
		})
		cfgCtx := sdkplugin.WithHostClient(context.Background(), pNil.cachedHostClient)
		require.NoError(t, pNil.ConfigureAuthHandler(cfgCtx, HandlerName, sdkplugin.ProviderConfig{
			BinaryName:        "scafctl",
			AuthCallbackPages: nil,
		}))
		pNil.httpClient = mockHTTP

		type browserOutcome struct {
			status int
			body   string
			err    error
		}
		nilBrowserCh := make(chan browserOutcome, 1)
		pNil.openBrowser = func(_ context.Context, authURL string) error {
			u, _ := url.Parse(authURL)
			go func() {
				resp, getErr := http.Get(u.Query().Get("redirect_uri") + "/?code=NIL-CODE&state=" + url.QueryEscape(u.Query().Get("state"))) //nolint:noctx
				if getErr != nil {
					nilBrowserCh <- browserOutcome{err: getErr}
					return
				}
				b, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				nilBrowserCh <- browserOutcome{status: resp.StatusCode, body: string(b), err: readErr}
			}()
			return nil
		}

		_, err := pNil.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.Error(t, err)
		nilOut := <-nilBrowserCh
		require.NoError(t, nilOut.err)
		assert.Equal(t, http.StatusServiceUnavailable, nilOut.status)
		assert.Contains(t, nilOut.body, "Authentication Failed")
		assert.NotContains(t, nilOut.body, "older-host-detail")

		// 2. Direct OAuth callback error + forged missing-state request rejected with 403 without aborting login
		pDirect, _, _ := newTestPlugin(t)
		_, wantFailure := configureCustomCallbackPages(t, pDirect)

		forgedStatusCh := make(chan int, 1)
		directCh := make(chan browserOutcome, 1)
		pDirect.openBrowser = func(_ context.Context, authURL string) error {
			u, _ := url.Parse(authURL)
			redirectURI := u.Query().Get("redirect_uri")
			state := u.Query().Get("state")
			go func() {
				// Forged request with wrong state must get 403 and NOT abort login
				forgedResp, fErr := http.Get(redirectURI + "/?error=forged_abort&state=wrong-state") //nolint:noctx
				if fErr == nil {
					_ = forgedResp.Body.Close()
					forgedStatusCh <- forgedResp.StatusCode
				}
				// Real callback with matching state and OAuth error
				resp, getErr := http.Get(redirectURI + "/?error=access_denied&error_description=user+declined+consent&state=" + url.QueryEscape(state)) //nolint:noctx
				if getErr != nil {
					directCh <- browserOutcome{err: getErr}
					return
				}
				b, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				directCh <- browserOutcome{status: resp.StatusCode, body: string(b), err: readErr}
			}()
			return nil
		}

		_, err = pDirect.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_denied")
		assert.Equal(t, http.StatusForbidden, <-forgedStatusCh)

		directOut := <-directCh
		require.NoError(t, directOut.err)
		assert.Equal(t, http.StatusBadRequest, directOut.status)
		assert.Equal(t, wantFailure, directOut.body)
		assert.NotContains(t, directOut.body, "user declined consent")
	})

	t.Run("in-flight callback during context cancellation drains 503 FailureHTML cleanly", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		exchangeEntered := make(chan struct{})
		releaseExchange := make(chan struct{})

		p, _, _ := newTestPlugin(t)
		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				close(exchangeEntered)
				<-releaseExchange
				return nil, context.Canceled
			},
		}
		_, wantFailure := configureCustomCallbackPages(t, p)

		type browserOutcome struct {
			status int
			body   string
			err    error
		}
		browserCh := make(chan browserOutcome, 1)
		p.openBrowser = func(_ context.Context, authURL string) error {
			u, _ := url.Parse(authURL)
			go func() {
				resp, getErr := http.Get(u.Query().Get("redirect_uri") + "/?code=CANCEL-CODE&state=" + url.QueryEscape(u.Query().Get("state"))) //nolint:noctx
				if getErr != nil {
					browserCh <- browserOutcome{err: getErr}
					return
				}
				b, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				browserCh <- browserOutcome{status: resp.StatusCode, body: string(b), err: readErr}
			}()
			return nil
		}

		loginCtx, cancelLogin := context.WithCancel(context.Background())
		loginDone := make(chan error, 1)
		go func() {
			_, err := p.Login(loginCtx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
			loginDone <- err
		}()

		<-exchangeEntered
		cancelLogin()
		close(releaseExchange)

		require.Error(t, <-loginDone)
		out := <-browserCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusServiceUnavailable, out.status)
		assert.Equal(t, wantFailure, out.body)
	})

	t.Run("post-callback panic still flushes 503 FailureHTML via deferred Shutdown", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		p, _, _ := newTestPlugin(t)
		_, wantFailure := configureCustomCallbackPages(t, p)
		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				panic("simulated post-callback panic")
			},
		}

		type browserOutcome struct {
			status int
			body   string
			err    error
		}
		browserCh := make(chan browserOutcome, 1)
		p.openBrowser = func(_ context.Context, authURL string) error {
			u, _ := url.Parse(authURL)
			redirectURI := u.Query().Get("redirect_uri")
			state := u.Query().Get("state")
			go func() {
				resp, getErr := http.Get(redirectURI + "/?code=PANIC-CODE&state=" + url.QueryEscape(state)) //nolint:noctx
				if getErr != nil {
					browserCh <- browserOutcome{err: getErr}
					return
				}
				b, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				browserCh <- browserOutcome{status: resp.StatusCode, body: string(b), err: readErr}
			}()
			return nil
		}

		assert.PanicsWithValue(t, "simulated post-callback panic", func() {
			_, _ = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		})

		out := <-browserCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusServiceUnavailable, out.status)
		assert.Equal(t, wantFailure, out.body)
	})

	t.Run("honors valid CallbackPort and falls back to ephemeral port on out-of-range values", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "localhost:0")
		require.NoError(t, err)
		wantedPort := lis.Addr().(*net.TCPAddr).Port
		require.NoError(t, lis.Close())

		p, _, mockHTTP := newTestPlugin(t)
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "port-at",
			RefreshToken: "port-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      makeTestIDToken(map[string]any{"sub": "sub-port", "email": "port@example.com"}),
		})
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "ephemeral-at",
			RefreshToken: "ephemeral-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      makeTestIDToken(map[string]any{"sub": "sub-eph", "email": "eph@example.com"}),
		})

		var gotRedirect string
		p.openBrowser = func(_ context.Context, authURL string) error {
			u, _ := url.Parse(authURL)
			gotRedirect = u.Query().Get("redirect_uri")
			completeLoopbackCallback(t, authURL, "PORT-CODE")
			return nil
		}

		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:         auth.FlowInteractive,
			CallbackPort: wantedPort,
		}, nil)
		require.NoError(t, err)
		assert.Contains(t, gotRedirect, fmt.Sprintf(":%d", wantedPort))

		// Out-of-range port (<1024) falls back cleanly to an ephemeral port
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:         auth.FlowInteractive,
			CallbackPort: 80,
		}, nil)
		require.NoError(t, err)
		assert.NotContains(t, gotRedirect, ":80")
	})
}

func TestInteractiveLogin_BrowserPreference(t *testing.T) {
	t.Run("forwards LoginRequest.Browser over gRPC and preserves empty default", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		for _, wantBrowser := range []string{"msedge", "chrome", ""} {
			t.Run("browser="+wantBrowser, func(t *testing.T) {
				p, _, mockHTTP := newTestPlugin(t)
				mockHTTP.AddResponse(http.StatusOK, TokenResponse{
					AccessToken:  "br-at",
					RefreshToken: "br-rt",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					IDToken:      makeTestIDToken(map[string]any{"sub": "br-sub", "email": "br@example.com"}),
				})

				var gotBrowser string
				p.openBrowser = func(ctx context.Context, authURL string) error {
					gotBrowser = browserPreferenceFromContext(ctx)
					completeLoopbackCallback(t, authURL, "BROWSER-CODE")
					return nil
				}

				grpcClient := startPluginAuthGRPCServer(t, p)
				stream, err := grpcClient.Login(context.Background(), &proto.LoginRequest{
					HandlerName: HandlerName,
					Flow:        string(auth.FlowInteractive),
					Browser:     wantBrowser,
				})
				require.NoError(t, err)

				var gotResult *proto.LoginResult
				for {
					msg, recvErr := stream.Recv()
					if errors.Is(recvErr, io.EOF) {
						break
					}
					require.NoError(t, recvErr)
					require.Empty(t, msg.GetError())
					if r := msg.GetResult(); r != nil {
						gotResult = r
					}
				}
				require.NotNil(t, gotResult)
				assert.Equal(t, "br-sub", gotResult.GetClaims().GetSubject())
				assert.Equal(t, wantBrowser, gotBrowser)
			})
		}
	})

	t.Run("defaultBrowserOpener launches configured browser executable via oauth.OpenBrowserWithPreference", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX shell script browser stub requires unix-like OS")
		}
		clearAmbientGCPEnv(t)

		tmpDir := t.TempDir()
		urlCaptureFile := filepath.Join(tmpDir, "opened-url.txt")
		fakeBrowserScript := filepath.Join(tmpDir, "fake-browser")
		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$1\" > %q\n", urlCaptureFile)
		require.NoError(t, os.WriteFile(fakeBrowserScript, []byte(script), 0o755)) //nolint:gosec // executable test stub

		p, _, mockHTTP := newTestPlugin(t)
		p.openBrowser = nil // exercise production defaultBrowserOpener
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "exec-at",
			RefreshToken: "exec-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      makeTestIDToken(map[string]any{"sub": "exec-sub", "email": "exec@example.com"}),
		})

		loginDone := make(chan error, 1)
		go func() {
			_, loginErr := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
				Flow:    auth.FlowInteractive,
				Browser: fakeBrowserScript,
				Timeout: 10 * time.Second,
			}, nil)
			loginDone <- loginErr
		}()

		var launchedURL string
		require.Eventually(t, func() bool {
			b, err := os.ReadFile(urlCaptureFile) //nolint:gosec // test temp file
			if err != nil || len(b) == 0 {
				return false
			}
			launchedURL = string(b)
			return true
		}, 5*time.Second, 20*time.Millisecond, "configured browser executable must receive authorization URL")

		completeLoopbackCallback(t, launchedURL, "REAL-BROWSER-CODE")
		require.NoError(t, <-loginDone)
	})

	t.Run("defaultBrowserOpener logs warning via logr and falls back to system default when preferred browser fails", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("xdg-open PATH stub is linux-specific")
		}

		tmpDir := t.TempDir()
		fallbackFile := filepath.Join(tmpDir, "fallback-url.txt")
		fakeXdgOpen := filepath.Join(tmpDir, "xdg-open")
		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$1\" > %q\n", fallbackFile)
		require.NoError(t, os.WriteFile(fakeXdgOpen, []byte(script), 0o755)) //nolint:gosec // executable test stub
		t.Setenv("PATH", tmpDir)

		sink := &capturingLogSink{}
		ctx := logr.NewContext(context.Background(), logr.New(sink))
		targetURL := "https://accounts.google.com/o/oauth2/v2/auth?client_id=test"
		err := defaultBrowserOpener(withBrowserPreference(ctx, filepath.Join(tmpDir, "missing-browser")), targetURL)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			b, readErr := os.ReadFile(fallbackFile) //nolint:gosec // test temp file
			return readErr == nil && string(b) == targetURL
		}, 3*time.Second, 20*time.Millisecond, "xdg-open fallback must receive URL")

		assert.Contains(t, sink.Joined(), "falling back to system default browser")
	})
}

func TestStatelessPerRPCSettingsAndProfiles(t *testing.T) {
	t.Run("preserves ConfigureAuthHandler defaults when per-RPC settings are absent and resets on explicit empty settings over gRPC", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		dir := t.TempDir()
		workSAFile := filepath.Join(dir, "work-sa.json")
		workSA := ServiceAccountKey{
			Type:         "service_account",
			ProjectID:    "work-proj",
			PrivateKeyID: "kid-work",
			PrivateKey:   generateTestRSAKey(t),
			ClientEmail:  "work-sa@work-proj.iam.gserviceaccount.com",
			ClientID:     "work-sa-id",
		}
		saBytes, err := json.Marshal(workSA)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(workSAFile, saBytes, 0o600))

		p, _, mockHTTP := newTestPlugin(t)
		cfgCtx := sdkplugin.WithHostClient(context.Background(), p.cachedHostClient)
		require.NoError(t, p.ConfigureAuthHandler(cfgCtx, HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
			Profile:    "work",
			Settings: map[string]json.RawMessage{
				HandlerName: json.RawMessage(fmt.Sprintf(`{"project":"work-proj","serviceAccountKeyFile":%q}`, workSAFile)),
			},
		}))
		p.httpClient = mockHTTP

		grpcClient := startPluginAuthGRPCServer(t, p)

		// 1. Legacy host sending nil Settings falls back to ConfigureAuthHandler's work-sa.json.
		stLegacy, err := grpcClient.GetStatus(context.Background(), &proto.GetStatusRequest{
			HandlerName: HandlerName,
			Profile:     "work",
			Settings:    nil,
		})
		require.NoError(t, err)
		assert.True(t, stLegacy.GetAuthenticated())
		assert.Equal(t, "work-sa@work-proj.iam.gserviceaccount.com", stLegacy.GetClaims().GetEmail())

		// 2. Host sending explicit "{}" Settings for default profile must NOT leak work-sa.json!
		stDefault, err := grpcClient.GetStatus(context.Background(), &proto.GetStatusRequest{
			HandlerName: HandlerName,
			Profile:     "",
			Settings:    []byte(`{}`),
		})
		require.NoError(t, err)
		assert.False(t, stDefault.GetAuthenticated(), "explicit empty per-RPC settings must not inherit ConfigureAuthHandler's serviceAccountKeyFile")

		// 3. Nested handler settings, null nested value, and malformed settings
		nestedCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"clientId":"nested-cid","project":"nested-proj"}`),
		})
		effCfg, err := p.effectiveConfig(nestedCtx)
		require.NoError(t, err)
		assert.Equal(t, "nested-cid", effCfg.ClientID)
		assert.Equal(t, "nested-proj", effCfg.Project)
		assert.Equal(t, "work-proj", p.config.Project, "p.config must never be mutated")

		nullCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			HandlerName: json.RawMessage(`null`),
		})
		nullCfg, err := p.effectiveConfig(nullCtx)
		require.NoError(t, err)
		assert.Empty(t, nullCfg.ServiceAccountKeyFile)

		badCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"impersonateServiceAccount":"bad"}`),
		})
		_, err = p.effectiveConfig(badCtx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "impersonateServiceAccount")
	})

	t.Run("isolates Login, GetStatus, GetToken, DetectAvailableFlows, ListCachedTokens, PurgeExpiredTokens, and Logout across profiles under -race", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		dir := t.TempDir()

		// Create SA key for profile "deploy"
		deploySAFile := filepath.Join(dir, "deploy-sa.json")
		deploySA := ServiceAccountKey{
			Type:         "service_account",
			ProjectID:    "deploy-proj",
			PrivateKeyID: "kid-deploy",
			PrivateKey:   generateTestRSAKey(t),
			ClientEmail:  "deploy@deploy-proj.iam.gserviceaccount.com",
			ClientID:     "deploy-cid",
		}
		deploySABytes, _ := json.Marshal(deploySA)
		require.NoError(t, os.WriteFile(deploySAFile, deploySABytes, 0o600))

		// Create WIF config for profile "ci"
		subjectTokenFile := filepath.Join(dir, "oidc-token")
		require.NoError(t, os.WriteFile(subjectTokenFile, []byte("oidc-jwt-assertion"), 0o600))
		ciWIFFile := filepath.Join(dir, "ci-wif.json")
		ciWIF := ExternalAccountConfig{
			Type:             "external_account",
			Audience:         "//iam.googleapis.com/projects/999/locations/global/workloadIdentityPools/p/providers/pr",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
			CredentialSource: CredentialSource{File: subjectTokenFile},
		}
		ciWIFBytes, _ := json.Marshal(ciWIF)
		require.NoError(t, os.WriteFile(ciWIFFile, ciWIFBytes, 0o600))

		p, fake, _ := newTestPlugin(t)
		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, endpoint string, data url.Values) (*http.Response, error) {
				switch {
				case endpoint == stsEndpoint:
					return jsonHTTPResponse(http.StatusOK, STSTokenResponse{
						AccessToken: "wi-ci-token",
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					}), nil
				case data.Get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer":
					return jsonHTTPResponse(http.StatusOK, TokenResponse{
						AccessToken: "sa-deploy-token",
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					}), nil
				case data.Get("grant_type") == "authorization_code":
					clientID := data.Get("client_id")
					return jsonHTTPResponse(http.StatusOK, TokenResponse{
						AccessToken:  "at-" + clientID,
						RefreshToken: "rt-" + clientID,
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						IDToken: makeTestIDToken(map[string]any{
							"sub":   "sub-" + clientID,
							"email": clientID + "@example.com",
						}),
					}), nil
				case data.Get("grant_type") == "refresh_token":
					rt := data.Get("refresh_token")
					return jsonHTTPResponse(http.StatusOK, TokenResponse{
						AccessToken: "refreshed-" + rt,
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					}), nil
				default:
					return jsonHTTPResponse(http.StatusOK, map[string]string{}), nil
				}
			},
		}
		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "PROF-AUTH-CODE")
			return nil
		}

		grpcClient := startPluginAuthGRPCServer(t, p)

		// Log in interactive user sessions on two distinct profiles ("work" and "personal")
		for _, prof := range []string{"work", "personal"} {
			settingsJSON, _ := json.Marshal(map[string]any{
				"clientId":      prof + "-client",
				"clientSecret":  prof + "-secret",
				"project":       prof + "-proj",
				"defaultScopes": []string{"openid", "email"},
			})
			stream, err := grpcClient.Login(context.Background(), &proto.LoginRequest{
				HandlerName: HandlerName,
				Profile:     prof,
				Flow:        string(auth.FlowInteractive),
				Settings:    settingsJSON,
			})
			require.NoError(t, err)
			for {
				msg, recvErr := stream.Recv()
				if errors.Is(recvErr, io.EOF) {
					break
				}
				require.NoError(t, recvErr)
				require.Empty(t, msg.GetError())
			}
		}

		deploySettings, _ := json.Marshal(map[string]any{"serviceAccountKeyFile": deploySAFile})
		ciSettings, _ := json.Marshal(map[string]any{"externalAccountFile": ciWIFFile})
		workSettings, _ := json.Marshal(map[string]any{"clientId": "work-client", "clientSecret": "work-secret"})
		personalSettings, _ := json.Marshal(map[string]any{"clientId": "personal-client", "clientSecret": "personal-secret"})

		// Concurrent multi-profile GetStatus, GetToken, DetectAvailableFlows, and ListCachedTokens over gRPC
		const workers = 6
		var wg sync.WaitGroup
		for range workers {
			wg.Add(4)
			go func() {
				defer wg.Done()
				st, err := grpcClient.GetStatus(context.Background(), &proto.GetStatusRequest{
					HandlerName: HandlerName,
					Profile:     "work",
					Settings:    workSettings,
				})
				assert.NoError(t, err)
				assert.True(t, st.GetAuthenticated())
				assert.Equal(t, string(auth.FlowInteractive), st.GetFlow())
				assert.Equal(t, "work-client@example.com", st.GetClaims().GetEmail())

				tok, err := grpcClient.GetToken(context.Background(), &proto.GetTokenRequest{
					HandlerName: HandlerName,
					Profile:     "work",
					Scope:       "https://www.googleapis.com/auth/cloud-platform",
					Settings:    workSettings,
				})
				assert.NoError(t, err)
				assert.Equal(t, "at-work-client", tok.GetAccessToken())
				assert.Equal(t, string(auth.FlowInteractive), tok.GetFlow())
				assert.NotEmpty(t, tok.GetSessionId())
			}()
			go func() {
				defer wg.Done()
				st, err := grpcClient.GetStatus(context.Background(), &proto.GetStatusRequest{
					HandlerName: HandlerName,
					Profile:     "personal",
					Settings:    personalSettings,
				})
				assert.NoError(t, err)
				assert.True(t, st.GetAuthenticated())
				assert.Equal(t, string(auth.FlowInteractive), st.GetFlow())
				assert.Equal(t, "personal-client@example.com", st.GetClaims().GetEmail())

				tok, err := grpcClient.GetToken(context.Background(), &proto.GetTokenRequest{
					HandlerName:  HandlerName,
					Profile:      "personal",
					Scope:        "https://www.googleapis.com/auth/cloud-platform",
					ForceRefresh: true,
					Settings:     personalSettings,
				})
				assert.NoError(t, err)
				assert.Equal(t, "refreshed-rt-personal-client", tok.GetAccessToken())
				assert.Equal(t, string(auth.FlowInteractive), tok.GetFlow())
				assert.NotEmpty(t, tok.GetSessionId())
			}()
			go func() {
				defer wg.Done()
				flowsResp, err := grpcClient.DetectAvailableFlows(context.Background(), &proto.DetectAvailableFlowsRequest{
					HandlerName: HandlerName,
					Profile:     "deploy",
					Settings:    deploySettings,
				})
				assert.NoError(t, err)
				assert.Empty(t, flowsResp.GetError())
				if assert.Len(t, flowsResp.GetFlows(), 1) {
					assert.Equal(t, string(auth.FlowServicePrincipal), flowsResp.GetFlows()[0].GetFlow())
				}

				tok, err := grpcClient.GetToken(context.Background(), &proto.GetTokenRequest{
					HandlerName: HandlerName,
					Profile:     "deploy",
					Scope:       "https://www.googleapis.com/auth/cloud-platform",
					Settings:    deploySettings,
				})
				assert.NoError(t, err)
				assert.Equal(t, "sa-deploy-token", tok.GetAccessToken())
				assert.Equal(t, string(auth.FlowServicePrincipal), tok.GetFlow())
			}()
			go func() {
				defer wg.Done()
				flowsResp, err := grpcClient.DetectAvailableFlows(context.Background(), &proto.DetectAvailableFlowsRequest{
					HandlerName: HandlerName,
					Profile:     "ci",
					Settings:    ciSettings,
				})
				assert.NoError(t, err)
				assert.Empty(t, flowsResp.GetError())
				if assert.Len(t, flowsResp.GetFlows(), 1) {
					assert.Equal(t, string(auth.FlowWorkloadIdentity), flowsResp.GetFlows()[0].GetFlow())
				}

				tok, err := grpcClient.GetToken(context.Background(), &proto.GetTokenRequest{
					HandlerName: HandlerName,
					Profile:     "ci",
					Scope:       "https://www.googleapis.com/auth/cloud-platform",
					Settings:    ciSettings,
				})
				assert.NoError(t, err)
				assert.Equal(t, "wi-ci-token", tok.GetAccessToken())
				assert.Equal(t, string(auth.FlowWorkloadIdentity), tok.GetFlow())
			}()
		}
		wg.Wait()

		// ListCachedTokens & Logout on "work" must not touch "personal"
		workList, err := grpcClient.ListCachedTokens(context.Background(), &proto.ListCachedTokensRequest{
			HandlerName: HandlerName,
			Profile:     "work",
		})
		require.NoError(t, err)
		assert.Len(t, workList.GetTokens(), 2) // 1 refresh + 1 access

		_, err = grpcClient.Logout(context.Background(), &proto.LogoutRequest{
			HandlerName: HandlerName,
			Profile:     "work",
		})
		require.NoError(t, err)

		stWorkAfter, err := grpcClient.GetStatus(context.Background(), &proto.GetStatusRequest{
			HandlerName: HandlerName,
			Profile:     "work",
			Settings:    workSettings,
		})
		require.NoError(t, err)
		assert.False(t, stWorkAfter.GetAuthenticated())

		stPersonalAfter, err := grpcClient.GetStatus(context.Background(), &proto.GetStatusRequest{
			HandlerName: HandlerName,
			Profile:     "personal",
			Settings:    personalSettings,
		})
		require.NoError(t, err)
		assert.True(t, stPersonalAfter.GetAuthenticated(), "logging out 'work' profile must keep 'personal' session intact")

		// Seed an expired entry in "personal" only and verify PurgeExpiredTokens is profile-scoped
		ctxPersonal := auth.WithProfile(context.Background(), "personal")
		expBytes, _ := json.Marshal(tokenCacheEntry{
			AccessToken: "exp",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(-time.Hour),
			CachedAt:    time.Now().Add(-2 * time.Hour),
		})
		fake.mu.Lock()
		fake.secrets[p.tokenCachePrefix(ctxPersonal)+"expired-1"] = string(expBytes)
		fake.secrets[SecretKeyTokenPrefix+"default-expired"] = string(expBytes)
		fake.mu.Unlock()

		purgePersonal, err := grpcClient.PurgeExpiredTokens(context.Background(), &proto.PurgeExpiredTokensRequest{
			HandlerName: HandlerName,
			Profile:     "personal",
		})
		require.NoError(t, err)
		assert.Equal(t, int32(1), purgePersonal.GetPurgedCount())

		fake.mu.Lock()
		_, defaultStillThere := fake.secrets[SecretKeyTokenPrefix+"default-expired"]
		fake.mu.Unlock()
		assert.True(t, defaultStillThere, "purging 'personal' profile must not delete default profile entries")
	})
}

func TestHTTPClientCache_IsolationCircuitBreakerAndEviction(t *testing.T) {
	t.Run("reuses init client on matching config, isolates distinct per-RPC configs, preserves circuit breaker, and closes idle conns on eviction and StopAuthHandler", func(t *testing.T) {
		var failingHits atomic.Int32
		failingTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			failingHits.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server_error"}`))
		}))
		defer failingTS.Close()

		p := &Plugin{clientCacheSize: 2}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
			Settings: map[string]json.RawMessage{
				HandlerName: json.RawMessage(`{"httpClient":{"timeout":"1ns","retryMax":0}}`),
			},
		}))
		t.Cleanup(func() { _ = p.StopAuthHandler(context.Background(), HandlerName) })
		initClient := p.httpClient

		// Same HTTP config reuses initClient
		sameCfg, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"1ns","retryMax":0}}`))
		require.NoError(t, err)
		gotSame, err := p.httpClientForConfig(context.Background(), sameCfg)
		require.NoError(t, err)
		assert.Same(t, initClient, gotSame)

		// Invalid httpClient config fails fast
		badCfg, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"not-a-duration"}}`))
		require.NoError(t, err)
		_, err = p.httpClientForConfig(context.Background(), badCfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid timeout duration")

		// Circuit breaker state persists across separate per-RPC Config instances sharing effective settings
		cbJSON := `{"httpClient":{"timeout":"2s","retryMax":1,"retryWaitMin":"1ms","retryWaitMax":"2ms","allowPrivateIPs":true,"enableCircuitBreaker":true,"circuitBreakerMaxFailures":2,"circuitBreakerOpenTimeout":"1m"}}`
		cbCfg1, err := parseHandlerConfig([]byte(cbJSON))
		require.NoError(t, err)
		cbCfg2, err := parseHandlerConfig([]byte(cbJSON))
		require.NoError(t, err)

		hc1, err := p.httpClientForConfig(context.Background(), cbCfg1)
		require.NoError(t, err)
		hc2, err := p.httpClientForConfig(context.Background(), cbCfg2)
		require.NoError(t, err)
		assert.Same(t, hc1, hc2)

		for range 2 {
			r, postErr := hc1.PostForm(context.Background(), failingTS.URL, url.Values{"grant_type": {"refresh_token"}})
			if r != nil {
				_ = r.Body.Close()
			}
			require.Error(t, postErr)
		}
		hitsBeforeOpen := failingHits.Load()
		_, err3 := hc2.PostForm(context.Background(), failingTS.URL, url.Values{"grant_type": {"refresh_token"}})
		require.Error(t, err3)
		assert.ErrorIs(t, err3, httpc.ErrCircuitBreakerOpen)
		assert.Equal(t, hitsBeforeOpen, failingHits.Load())

		// Bounded LRU eviction & StopAuthHandler close idle connections
		var closedConns atomic.Int32
		keepAliveTS := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"123"}`))
		}))
		keepAliveTS.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				closedConns.Add(1)
			}
		}
		keepAliveTS.Start()
		defer keepAliveTS.Close()

		evictPlugin := &Plugin{clientCacheSize: 2}
		require.NoError(t, evictPlugin.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{BinaryName: "scafctl"}))

		cfgK1, _ := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"4s","allowPrivateIPs":true}}`))
		cfgK2, _ := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"5s","allowPrivateIPs":true}}`))
		cfgK3, _ := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"6s","allowPrivateIPs":true}}`))

		c1, err := evictPlugin.httpClientForConfig(context.Background(), cfgK1)
		require.NoError(t, err)
		c2, err := evictPlugin.httpClientForConfig(context.Background(), cfgK2)
		require.NoError(t, err)

		for _, c := range []HTTPClient{c1, c2} {
			r, getErr := c.Get(context.Background(), keepAliveTS.URL, nil)
			require.NoError(t, getErr)
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}
		assert.Equal(t, int32(0), closedConns.Load())

		// Touch K1 so K2 is LRU, then insert K3
		_, _ = evictPlugin.httpClientForConfig(context.Background(), cfgK1)
		_, err = evictPlugin.httpClientForConfig(context.Background(), cfgK3)
		require.NoError(t, err)
		assert.Equal(t, 2, evictPlugin.httpClientCache.Len())

		require.Eventually(t, func() bool {
			return closedConns.Load() == 1
		}, 2*time.Second, 10*time.Millisecond)

		require.NoError(t, evictPlugin.StopAuthHandler(context.Background(), HandlerName))
		require.Eventually(t, func() bool {
			return closedConns.Load() == 2
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("concurrent -race stress over bounded HTTP client cache", func(t *testing.T) {
		p := &Plugin{clientCacheSize: 4}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{BinaryName: "scafctl"}))

		var wg sync.WaitGroup
		for g := range 16 {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for i := range 15 {
					sec := ((id + i) % 8) + 1
					cfg, err := parseHandlerConfig([]byte(fmt.Sprintf(`{"httpClient":{"timeout":"%ds","allowPrivateIPs":true}}`, sec)))
					assert.NoError(t, err)
					hc, err := p.httpClientForConfig(context.Background(), cfg)
					assert.NoError(t, err)
					assert.NotNil(t, hc)
				}
			}(g)
		}
		wg.Wait()
		assert.LessOrEqual(t, p.httpClientCache.Len(), 4)
		require.NoError(t, p.StopAuthHandler(context.Background(), HandlerName))
	})
}

func TestSessionConsistency_AccountReplacementAndBoundedCleanup(t *testing.T) {
	clearAmbientGCPEnv(t)

	aliceJWT := makeTestIDToken(map[string]any{"sub": "alice-sub", "email": "alice@example.com"})
	bobJWT := makeTestIDToken(map[string]any{"sub": "bob-sub", "email": "bob@example.com"})

	t.Run("metadata write failure on replacement login preserves Alice session and rolls back unreferenced refresh token", func(t *testing.T) {
		p, fake, mockHTTP := newTestPlugin(t)
		wantSuccess, wantFailure := configureCustomCallbackPages(t, p)

		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at-1",
			RefreshToken: "alice-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "bob-at-1",
			RefreshToken: "bob-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      bobJWT,
		})
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at-2",
			RefreshToken: "alice-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})

		runWithBrowserCapture := func() <-chan int {
			ch := make(chan int, 1)
			p.openBrowser = func(_ context.Context, authURL string) error {
				u, _ := url.Parse(authURL)
				go func() {
					resp, getErr := http.Get(u.Query().Get("redirect_uri") + "/?code=REPLACE-CODE&state=" + url.QueryEscape(u.Query().Get("state"))) //nolint:noctx
					if getErr != nil {
						ch <- 0
						return
					}
					b, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						assert.Equal(t, wantSuccess, string(b))
					} else {
						assert.Equal(t, wantFailure, string(b))
					}
					ch <- resp.StatusCode
				}()
				return nil
			}
			return ch
		}

		aliceCodeCh := runWithBrowserCapture()
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, <-aliceCodeCh)

		// Fail metadata write during Bob's replacement login
		fake.mu.Lock()
		fake.setSecretKeyErr = map[string]error{
			SecretKeyMetadata: errors.New("metadata write quota exceeded"),
		}
		fake.mu.Unlock()

		bobCodeCh := runWithBrowserCapture()
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.Error(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, <-bobCodeCh)

		// Alice's session must remain active and consistent
		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		require.True(t, st.Authenticated)
		assert.Equal(t, "alice@example.com", st.Claims.Email)

		tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:        "https://www.googleapis.com/auth/cloud-platform",
			ForceRefresh: true,
		})
		require.NoError(t, err)
		assert.Equal(t, "alice-at-2", tok.AccessToken)
		assert.Equal(t, "alice-rt", mockHTTP.GetRequests()[2].Data.Get("refresh_token"))
	})

	t.Run("logoutIfSessionMatches requires positive session proof and bounded cleanup timeout prevents hangs", func(t *testing.T) {
		p, fake, mockHTTP := newTestPlugin(t)
		p.cleanupTimeout = 40 * time.Millisecond

		_, err := p.storeCredentialsWithClaims(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "alice-at",
			RefreshToken: "alice-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		}, auth.FlowInteractive, []string{"openid"}, "alice-session", DefaultADCClientID, nil)
		require.NoError(t, err)
		require.NoError(t, cacheSetWithPrefix(
			context.Background(),
			p.hostClient(context.Background()),
			p.tokenCachePrefix(context.Background()),
			buildCacheKey(auth.FlowInteractive, fingerprintHash(DefaultADCClientID), ""),
			&auth.Token{
				AccessToken: "alice-at",
				TokenType:   "Bearer",
				ExpiresAt:   time.Now().Add(time.Hour),
				Scope:       "openid",
				Flow:        auth.FlowInteractive,
				SessionID:   "alice-session",
			},
		))

		// Non-matching session ID does not wipe Alice's session
		p.logoutIfSessionMatches(context.Background(), "stale-session")
		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, st.Authenticated)

		// Transient GetSecret error does not wipe Alice's session
		fake.mu.Lock()
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyMetadata {
				return errors.New("transient secret store error")
			}
			return nil
		}
		fake.mu.Unlock()
		p.logoutIfSessionMatches(context.Background(), "alice-session")
		fake.mu.Lock()
		fake.getSecretFunc = nil
		fake.mu.Unlock()

		st, err = p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, st.Authenticated)

		// Matching session ID wipes Alice's session
		p.logoutIfSessionMatches(context.Background(), "alice-session")
		st, err = p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, st.Authenticated)

		// Stalled DeleteSecret during failed metadata commit honors bounded cleanupTimeout
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "bob-at",
			RefreshToken: "bob-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      bobJWT,
		})
		deleteDeadlineCh := make(chan bool, 1)
		fake.mu.Lock()
		fake.setSecretKeyErr = map[string]error{SecretKeyMetadata: errors.New("meta fail")}
		fake.deleteSecretFunc = func(ctx context.Context, _ string) error {
			_, hasDeadline := ctx.Deadline()
			select {
			case deleteDeadlineCh <- hasDeadline:
			default:
			}
			<-ctx.Done()
			return ctx.Err()
		}
		fake.mu.Unlock()

		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "BOUNDED-CLEANUP-CODE")
			return nil
		}
		started := time.Now()
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.Error(t, err)
		assert.Less(t, time.Since(started), 2*time.Second)
		assert.True(t, <-deleteDeadlineCh)
	})
}

func TestCredentialPrecedence_EnvFallbackAndFailClosed(t *testing.T) {
	t.Run("Config.WasSet and profileOrEnv honor explicit config over env and fall back when unset or empty", func(t *testing.T) {
		var nilCfg *Config
		assert.False(t, nilCfg.WasSet("serviceAccountKeyFile"))

		var parsed Config
		require.NoError(t, json.Unmarshal([]byte(`{"serviceAccountKeyFile":"","project":"proj-1"}`), &parsed))
		assert.False(t, parsed.WasSet("serviceAccountKeyFile"))
		assert.True(t, parsed.WasSet("project"))
		assert.False(t, parsed.WasSet("externalAccountFile"))

		t.Setenv(EnvGoogleApplicationCredentials, "/env/sa.json")
		t.Setenv(EnvGoogleExternalAccount, "/env/wif.json")

		// Empty string (even if explicitly set in JSON) falls back to env var per Issue #12
		assert.Equal(t, "/env/sa.json", parsed.profileOrEnv(parsed.ServiceAccountKeyFile, "serviceAccountKeyFile", EnvGoogleApplicationCredentials))
		assert.Equal(t, "/env/wif.json", parsed.profileOrEnv(parsed.ExternalAccountFile, "externalAccountFile", EnvGoogleExternalAccount))

		// Explicit non-empty profile path overrides env var
		parsed.ServiceAccountKeyFile = "/profile/sa.json"
		parsed.ExternalAccountFile = "/profile/wif.json"
		assert.Equal(t, "/profile/sa.json", parsed.profileOrEnv(parsed.ServiceAccountKeyFile, "serviceAccountKeyFile", EnvGoogleApplicationCredentials))
		assert.Equal(t, "/profile/wif.json", parsed.profileOrEnv(parsed.ExternalAccountFile, "externalAccountFile", EnvGoogleExternalAccount))
	})

	t.Run("profile serviceAccountKeyFile and externalAccountFile beat env vars and GCE metadata; broken explicit files fail closed", func(t *testing.T) {
		dir := t.TempDir()
		rsaKey := generateTestRSAKey(t)

		writeSA := func(name, email string) string {
			p := filepath.Join(dir, name)
			b, _ := json.Marshal(ServiceAccountKey{
				Type:         "service_account",
				ProjectID:    "proj",
				PrivateKeyID: "kid",
				PrivateKey:   rsaKey,
				ClientEmail:  email,
				ClientID:     "cid-" + name,
			})
			require.NoError(t, os.WriteFile(p, b, 0o600))
			return p
		}
		writeWIF := func(name, aud string) string {
			tokFile := filepath.Join(dir, name+"-subj")
			require.NoError(t, os.WriteFile(tokFile, []byte("jwt-"+name), 0o600))
			p := filepath.Join(dir, name)
			b, _ := json.Marshal(ExternalAccountConfig{
				Type:             "external_account",
				Audience:         aud,
				SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
				CredentialSource: CredentialSource{File: tokFile},
			})
			require.NoError(t, os.WriteFile(p, b, 0o600))
			return p
		}

		envSA := writeSA("env-sa.json", "env-sa@proj.iam.gserviceaccount.com")
		profSA := writeSA("prof-sa.json", "prof-sa@proj.iam.gserviceaccount.com")
		envWIF := writeWIF("env-wif.json", "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/env/providers/p")
		profWIF := writeWIF("prof-wif.json", "//iam.googleapis.com/projects/2/locations/global/workloadIdentityPools/prof/providers/p")

		// Also configure reachable GCE metadata server AND ambient gcloud_adc credentials!
		gcloudDir := filepath.Join(dir, "gcloud")
		require.NoError(t, os.MkdirAll(gcloudDir, 0o700))
		gcloudADCBytes, _ := json.Marshal(map[string]string{
			"type":          "authorized_user",
			"client_id":     "gcloud-cid",
			"client_secret": "gcloud-sec",
			"refresh_token": "gcloud-rt",
		})
		require.NoError(t, os.WriteFile(filepath.Join(gcloudDir, "application_default_credentials.json"), gcloudADCBytes, 0o600))
		t.Setenv(EnvCloudSDKConfig, gcloudDir)

		metaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(metadataFlavorHeader) != metadataFlavorValue {
				http.Error(w, "missing header", http.StatusForbidden)
				return
			}
			switch r.URL.Path {
			case "/computeMetadata/v1/instance/service-accounts/default/token":
				_ = json.NewEncoder(w).Encode(MetadataTokenResponse{AccessToken: "gce-meta-token", TokenType: "Bearer", ExpiresIn: 3600})
			case "/computeMetadata/v1/instance/service-accounts/default/email":
				_, _ = w.Write([]byte("gce-vm@proj.iam.gserviceaccount.com"))
			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(metaSrv.Close)
		t.Setenv(EnvGCEMetadataHost, metaSrv.Listener.Addr().String())

		p, _, _ := newTestPlugin(t)
		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, endpoint string, data url.Values) (*http.Response, error) {
				switch {
				case endpoint == stsEndpoint:
					return jsonHTTPResponse(http.StatusOK, STSTokenResponse{
						AccessToken: "sts-for-" + data.Get("audience"),
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					}), nil
				case data.Get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer":
					return jsonHTTPResponse(http.StatusOK, TokenResponse{
						AccessToken: "sa-jwt-token",
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					}), nil
				case data.Get("refresh_token") == "gcloud-rt":
					return jsonHTTPResponse(http.StatusOK, TokenResponse{
						AccessToken: "ambient-gcloud-token",
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					}), nil
				default:
					return jsonHTTPResponse(http.StatusOK, TokenResponse{AccessToken: "other", TokenType: "Bearer", ExpiresIn: 3600}), nil
				}
			},
		}

		// 1. Both GOOGLE_APPLICATION_CREDENTIALS and profile serviceAccountKeyFile set (and GCE metadata reachable):
		// profile serviceAccountKeyFile wins across Login, GetStatus, GetToken, and DetectAvailableFlows!
		t.Setenv(EnvGoogleApplicationCredentials, envSA)
		t.Setenv(EnvGoogleExternalAccount, "")

		profSASettings := map[string]json.RawMessage{
			"serviceAccountKeyFile": json.RawMessage(fmt.Sprintf("%q", profSA)),
		}
		profSACtx := sdkplugin.WithRequestSettings(auth.WithProfile(context.Background(), "sa-prof"), profSASettings)

		loginResp, err := p.Login(profSACtx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)
		assert.Equal(t, "prof-sa@proj.iam.gserviceaccount.com", loginResp.Claims.Email)

		st, err := p.GetStatus(profSACtx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		require.True(t, st.Authenticated)
		assert.Equal(t, auth.FlowServicePrincipal, st.Flow)
		assert.Equal(t, "prof-sa@proj.iam.gserviceaccount.com", st.Claims.Email)

		tok, err := p.GetToken(profSACtx, HandlerName, sdkplugin.TokenRequest{Scope: "https://www.googleapis.com/auth/cloud-platform"})
		require.NoError(t, err)
		assert.Equal(t, "sa-jwt-token", tok.AccessToken)
		assert.Equal(t, auth.FlowServicePrincipal, tok.Flow)

		flows, err := p.DetectAvailableFlows(profSACtx, HandlerName)
		require.NoError(t, err)
		require.Len(t, flows, 2)
		assert.Equal(t, auth.FlowServicePrincipal, flows[0].Flow, "service_principal must rank ahead of metadata")
		assert.Equal(t, auth.FlowMetadata, flows[1].Flow)
		assert.Contains(t, flows[0].Reason, "serviceAccountKeyFile")

		// Without GOOGLE_APPLICATION_CREDENTIALS shadowing CLOUDSDK_CONFIG, all 3 rank in precedence order
		t.Setenv(EnvGoogleApplicationCredentials, "")
		flowsWithGcloud, err := p.DetectAvailableFlows(profSACtx, HandlerName)
		require.NoError(t, err)
		require.Len(t, flowsWithGcloud, 3)
		assert.Equal(t, auth.FlowServicePrincipal, flowsWithGcloud[0].Flow)
		assert.Equal(t, auth.FlowMetadata, flowsWithGcloud[1].Flow)
		assert.Equal(t, auth.FlowGcloudADC, flowsWithGcloud[2].Flow)
		t.Setenv(EnvGoogleApplicationCredentials, envSA)

		// Empty profile serviceAccountKeyFile falls back to GOOGLE_APPLICATION_CREDENTIALS
		emptySACtx := sdkplugin.WithRequestSettings(auth.WithProfile(context.Background(), "env-fallback"), map[string]json.RawMessage{
			"serviceAccountKeyFile": json.RawMessage(`""`),
		})
		stEnv, err := p.GetStatus(emptySACtx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		require.True(t, stEnv.Authenticated)
		assert.Equal(t, "env-sa@proj.iam.gserviceaccount.com", stEnv.Claims.Email)

		// 2. Both GOOGLE_EXTERNAL_ACCOUNT and profile externalAccountFile set: profile externalAccountFile wins
		t.Setenv(EnvGoogleExternalAccount, envWIF)
		profWIFSettings := map[string]json.RawMessage{
			"externalAccountFile": json.RawMessage(fmt.Sprintf("%q", profWIF)),
		}
		profWIFCtx := sdkplugin.WithRequestSettings(auth.WithProfile(context.Background(), "wif-prof"), profWIFSettings)
		wiTok, err := p.GetToken(profWIFCtx, HandlerName, sdkplugin.TokenRequest{Scope: "https://www.googleapis.com/auth/cloud-platform"})
		require.NoError(t, err)
		assert.Contains(t, wiTok.AccessToken, "workloadIdentityPools/prof/", "profile externalAccountFile must override GOOGLE_EXTERNAL_ACCOUNT")
		assert.Equal(t, auth.FlowWorkloadIdentity, wiTok.Flow)

		// 3. Fail-closed: missing or wrong-type explicit serviceAccountKeyFile / externalAccountFile
		// must NOT fall back to GCE metadata or ambient gcloud_adc!
		t.Setenv(EnvGoogleExternalAccount, "")
		t.Setenv(EnvGoogleApplicationCredentials, "")

		wrongTypeFile := filepath.Join(dir, "wrong-type.json")
		require.NoError(t, os.WriteFile(wrongTypeFile, gcloudADCBytes, 0o600))

		for _, broken := range []struct {
			name     string
			settings map[string]json.RawMessage
			wantFlow auth.Flow
		}{
			{
				name:     "missing serviceAccountKeyFile",
				settings: map[string]json.RawMessage{"serviceAccountKeyFile": json.RawMessage(`"/nonexistent/sa.json"`)},
				wantFlow: auth.FlowServicePrincipal,
			},
			{
				name:     "wrong-type serviceAccountKeyFile",
				settings: map[string]json.RawMessage{"serviceAccountKeyFile": json.RawMessage(fmt.Sprintf("%q", wrongTypeFile))},
				wantFlow: auth.FlowServicePrincipal,
			},
			{
				name:     "missing externalAccountFile",
				settings: map[string]json.RawMessage{"externalAccountFile": json.RawMessage(`"/nonexistent/wif.json"`)},
				wantFlow: auth.FlowWorkloadIdentity,
			},
			{
				name:     "wrong-type externalAccountFile",
				settings: map[string]json.RawMessage{"externalAccountFile": json.RawMessage(fmt.Sprintf("%q", wrongTypeFile))},
				wantFlow: auth.FlowWorkloadIdentity,
			},
		} {
			t.Run(broken.name, func(t *testing.T) {
				bCtx := sdkplugin.WithRequestSettings(auth.WithProfile(context.Background(), "broken"), broken.settings)
				_, loginErr := p.Login(bCtx, HandlerName, sdkplugin.LoginRequest{}, nil)
				require.Error(t, loginErr, "Login must fail closed instead of falling through to metadata/browser")

				bSt, stErr := p.GetStatus(bCtx, HandlerName, sdkplugin.StatusRequest{})
				require.NoError(t, stErr)
				assert.False(t, bSt.Authenticated, "GetStatus must not report authenticated via ambient credentials")
				assert.Equal(t, broken.wantFlow, bSt.Flow)
				assert.NotEmpty(t, bSt.Reason)

				_, tokErr := p.GetToken(bCtx, HandlerName, sdkplugin.TokenRequest{Scope: "https://www.googleapis.com/auth/cloud-platform"})
				require.Error(t, tokErr, "GetToken must fail closed instead of minting ambient metadata/gcloud token")
			})
		}
	})
}

func TestConfigureAuthHandler_GRPCWireAndFlatSettings(t *testing.T) {
	clearAmbientGCPEnv(t)

	p, _, _ := newTestPlugin(t)
	grpcClient := startPluginAuthGRPCServer(t, p)

	resp, err := grpcClient.ConfigureAuthHandler(context.Background(), &proto.ConfigureAuthHandlerRequest{
		HandlerName: HandlerName,
		BinaryName:  "embedcli",
		Settings: map[string][]byte{
			"project":                   []byte(`"flat-project"`),
			"clientId":                  []byte(`"flat-client-id"`),
			"impersonateServiceAccount": []byte(`"flat-sa@proj.iam.gserviceaccount.com"`),
		},
		AuthCallbackPages: &proto.AuthCallbackPages{
			SuccessHtml: []byte("<html>FLAT-SUCCESS</html>"),
			FailureHtml: []byte("<html>FLAT-FAILURE</html>"),
		},
	})
	require.NoError(t, err)
	require.Empty(t, resp.GetError())

	cfg, err := p.effectiveConfig(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "flat-project", cfg.Project)
	assert.Equal(t, "flat-client-id", cfg.ClientID)
	assert.Equal(t, "flat-sa@proj.iam.gserviceaccount.com", cfg.ImpersonateServiceAccount)
	assert.Equal(t, "embedcli", p.binaryName())
	require.NotNil(t, p.callbackPages())
	assert.Equal(t, "<html>FLAT-SUCCESS</html>", string(p.callbackPages().SuccessHTML))
	assert.Equal(t, "<html>FLAT-FAILURE</html>", string(p.callbackPages().FailureHTML))
}

func TestGetStatus_ReadOnlyInvariantAndImpersonationOverride(t *testing.T) {
	clearAmbientGCPEnv(t)

	p, fake, mockHTTP := newTestPlugin(t)
	_, err := p.storeCredentialsWithClaims(context.Background(), &Config{
		Project:                   "orig-proj",
		ImpersonateServiceAccount: "stored-sa@proj.iam.gserviceaccount.com",
	}, &TokenResponse{
		AccessToken:  "init-at",
		RefreshToken: "probe-rt",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		IDToken:      makeTestIDToken(map[string]any{"sub": "u1", "email": "u1@example.com"}),
	}, auth.FlowInteractive, []string{"openid"}, "sess-ro", DefaultADCClientID, nil)
	require.NoError(t, err)

	// Snapshot secrets before GetStatus probes
	fake.mu.Lock()
	before := make(map[string]string, len(fake.secrets))
	for k, v := range fake.secrets {
		before[k] = v
	}
	fake.mu.Unlock()

	// 1. Uncached 200 OK refresh probe (even with rotated refresh_token!) must NOT mutate secrets/cache
	mockHTTP.AddResponse(http.StatusOK, TokenResponse{
		AccessToken:  "probed-at",
		RefreshToken: "rotated-during-status-rt",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	})
	st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.True(t, st.Authenticated)
	assert.Equal(t, "stored-sa@proj.iam.gserviceaccount.com", st.ClientID)

	fake.mu.Lock()
	assert.Equal(t, before, fake.secrets, "GetStatus 200 probe must not write cached tokens or rotate secrets")
	fake.mu.Unlock()

	// 2. Per-RPC settings override and clear impersonateServiceAccount
	mockHTTP.AddResponse(http.StatusOK, TokenResponse{AccessToken: "probed-at-2", TokenType: "Bearer", ExpiresIn: 3600})
	overrideCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
		"impersonateServiceAccount": json.RawMessage(`"override-sa@proj.iam.gserviceaccount.com"`),
	})
	stOverride, err := p.GetStatus(overrideCtx, HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, "override-sa@proj.iam.gserviceaccount.com", stOverride.ClientID)

	mockHTTP.AddResponse(http.StatusOK, TokenResponse{AccessToken: "probed-at-3", TokenType: "Bearer", ExpiresIn: 3600})
	clearedCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{})
	stCleared, err := p.GetStatus(clearedCtx, HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.Empty(t, stCleared.ClientID, "explicit empty per-RPC settings must clear stored impersonateServiceAccount")

	// 3. Uncached 400 invalid_grant probe must report unauthenticated WITHOUT wiping stored credentials
	mockHTTP.AddResponse(http.StatusBadRequest, TokenErrorResponse{
		Error:            "invalid_grant",
		ErrorDescription: "Token has been revoked",
	})
	stRevoked, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.False(t, stRevoked.Authenticated)
	assert.Equal(t, "expired or revoked", stRevoked.Reason)

	fake.mu.Lock()
	assert.Equal(t, before, fake.secrets, "GetStatus invalid_grant probe must not delete stored credentials")
	fake.mu.Unlock()
}

func TestGetToken_NoRefreshTokenSession_MinValidFor_AndImpersonationFlow(t *testing.T) {
	t.Run("interactive login without refresh_token serves cached access token and fails closed once expired", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		p, fake, mockHTTP := newTestPlugin(t)
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "short-lived-at",
			TokenType:   "Bearer",
			ExpiresIn:   600, // 10m (> DefaultMinValidFor 5m, < 15m custom MinValidFor)
			IDToken:     makeTestIDToken(map[string]any{"sub": "s-nort", "email": "nort@example.com"}),
		})
		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "NO-RT-CODE")
			return nil
		}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)

		// Default MinValidFor (5m) succeeds using cached access token
		tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope: "https://www.googleapis.com/auth/cloud-platform",
		})
		require.NoError(t, err)
		assert.Equal(t, "short-lived-at", tok.AccessToken)
		assert.Equal(t, auth.FlowInteractive, tok.Flow)
		assert.NotEmpty(t, tok.SessionID)

		// Larger MinValidFor (15m) rejects the 10m-remaining cached token, attempts mintToken,
		// and fails with ErrNotAuthenticated because no refresh_token was issued
		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:       "https://www.googleapis.com/auth/cloud-platform",
			MinValidFor: 15 * time.Minute,
		})
		require.ErrorIs(t, err, ErrNotAuthenticated)
		_ = fake
	})

	t.Run("impersonation preserves source Flow and SessionID instead of emitting undeclared impersonation flow", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		p, _, mockHTTP := newTestPlugin(t)
		p.config.ImpersonateServiceAccount = "imp-target@proj.iam.gserviceaccount.com"

		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "src-at",
			RefreshToken: "src-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      makeTestIDToken(map[string]any{"sub": "imp-u", "email": "imp@example.com"}),
		})
		mockHTTP.AddResponse(http.StatusOK, ImpersonationResponse{
			AccessToken: "imp-minted-at",
			ExpireTime:  time.Now().Add(time.Hour).Format(time.RFC3339),
		})
		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "IMP-CODE")
			return nil
		}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)

		tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope: "https://www.googleapis.com/auth/cloud-platform",
		})
		require.NoError(t, err)
		assert.Equal(t, "imp-minted-at", tok.AccessToken)
		assert.Equal(t, auth.FlowInteractive, tok.Flow)
		assert.NotEmpty(t, tok.SessionID)

		entries, err := p.ListCachedTokens(context.Background(), HandlerName)
		require.NoError(t, err)
		for _, entry := range entries {
			assert.NotEqual(t, auth.Flow("impersonation"), entry.Flow)
		}
	})
}

func TestSessionRotation_InconsistentSession_ConcurrentLogout_AndHelpers(t *testing.T) {
	t.Run("storeRotatedCredentials preserves Project and ImpersonateServiceAccount and skips stale sessions", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		p, _, _ := newTestPlugin(t)
		origCfg := &Config{
			Project:                   "keep-proj",
			ImpersonateServiceAccount: "keep-sa@proj.iam.gserviceaccount.com",
		}
		sessID, err := p.storeCredentialsWithClaims(context.Background(), origCfg, &TokenResponse{
			AccessToken:  "at-1",
			RefreshToken: "rt-1",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}, auth.FlowInteractive, []string{"openid"}, "sess-rot-1", DefaultADCClientID, &auth.Claims{Email: "a@example.com"})
		require.NoError(t, err)

		origMeta, err := p.loadMetadata(context.Background())
		require.NoError(t, err)
		require.Equal(t, sessID, origMeta.SessionID)

		// Rotate with an empty Config (simulating per-RPC GetToken without project/impersonation)
		require.NoError(t, p.storeRotatedCredentials(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "at-2",
			RefreshToken: "rt-2",
		}, origMeta, DefaultADCClientID))

		rotMeta, rt, hasRT, err := p.inspectStoredMetadataAndRefresh(context.Background())
		require.NoError(t, err)
		require.True(t, hasRT)
		assert.Equal(t, "rt-2", rt)
		assert.Equal(t, "keep-proj", rotMeta.Project)
		assert.Equal(t, "keep-sa@proj.iam.gserviceaccount.com", rotMeta.ImpersonateServiceAccount)

		// Replace session with sess-rot-2; stale rotation for sess-rot-1 must be a no-op
		_, err = p.storeCredentialsWithClaims(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "at-b",
			RefreshToken: "rt-b",
		}, auth.FlowInteractive, []string{"openid"}, "sess-rot-2", DefaultADCClientID, &auth.Claims{Email: "b@example.com"})
		require.NoError(t, err)

		require.NoError(t, p.storeRotatedCredentials(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "stale-at",
			RefreshToken: "stale-rt",
		}, origMeta, DefaultADCClientID))

		curMeta, curRT, _, err := p.inspectStoredMetadataAndRefresh(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "sess-rot-2", curMeta.SessionID)
		assert.Equal(t, "rt-b", curRT)
	})

	t.Run("RefreshTokenHash mismatch surfaces errInconsistentSession in GetStatus and GetToken", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		p, fake, _ := newTestPlugin(t)
		_, err := p.storeCredentialsWithClaims(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "at-1",
			RefreshToken: "good-rt",
		}, auth.FlowInteractive, []string{"openid"}, "sess-tamper", DefaultADCClientID, &auth.Claims{Email: "a@example.com"})
		require.NoError(t, err)

		meta, err := p.loadMetadata(context.Background())
		require.NoError(t, err)

		// Corrupt the versioned refresh token in the store so its hash no longer matches metadata
		fake.mu.Lock()
		fake.secrets[p.versionedRefreshKey(context.Background(), meta.RefreshTokenID)] = "tampered-rt"
		fake.mu.Unlock()

		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, st.Authenticated)
		assert.Equal(t, "stored session credentials are inconsistent", st.Reason)

		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "openid"})
		require.ErrorIs(t, err, ErrNotAuthenticated)
		assert.Contains(t, err.Error(), "inconsistent")
	})

	t.Run("in-flight Logout revocation does not wipe a newer replacement Login session", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		p, _, _ := newTestPlugin(t)
		revokeEntered := make(chan struct{})
		releaseRevoke := make(chan struct{})

		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, endpoint string, data url.Values) (*http.Response, error) {
				if endpoint == revokeEndpoint {
					close(revokeEntered)
					<-releaseRevoke
					return jsonHTTPResponse(http.StatusOK, map[string]string{}), nil
				}
				return jsonHTTPResponse(http.StatusOK, TokenResponse{
					AccessToken:  "new-login-at-" + data.Get("code"),
					RefreshToken: "new-login-rt",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					IDToken:      makeTestIDToken(map[string]any{"sub": "new-u", "email": "new@example.com"}),
				}), nil
			},
		}

		_, err := p.storeCredentialsWithClaims(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "old-at",
			RefreshToken: "old-rt",
		}, auth.FlowInteractive, []string{"openid"}, "old-session", DefaultADCClientID, &auth.Claims{Email: "old@example.com"})
		require.NoError(t, err)

		logoutDone := make(chan error, 1)
		go func() {
			logoutDone <- p.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{})
		}()

		<-revokeEntered

		// Replacement Login commits while Logout is paused in revokeRefreshTokenValue
		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "NEW-SESS")
			return nil
		}
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)

		close(releaseRevoke)
		require.NoError(t, <-logoutDone)

		// Replacement session and its seeded access token must still be intact
		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, st.Authenticated)
		assert.Equal(t, "new@example.com", st.Claims.Email)

		tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "openid"})
		require.NoError(t, err)
		assert.Equal(t, "new-login-at-NEW-SESS", tok.AccessToken)
	})

	t.Run("NewDefaultHTTPClientFromAppConfig, StopAuthHandler client reset, and sanitizeControlChars", func(t *testing.T) {
		cli, err := NewDefaultHTTPClientFromAppConfig(&httpc.AppConfig{Timeout: "5s"}, logr.Discard())
		require.NoError(t, err)
		require.NotNil(t, cli)
		require.NoError(t, cli.Close())

		_, err = NewDefaultHTTPClientFromAppConfig(&httpc.AppConfig{Timeout: "not-a-duration"}, logr.Discard())
		require.Error(t, err)

		// StopAuthHandler resets DefaultHTTPClient so post-stop calls construct a fresh client
		p := &Plugin{}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{}))
		firstHTTP, err := p.httpClientForConfig(context.Background(), p.baseConfig())
		require.NoError(t, err)
		require.NoError(t, p.StopAuthHandler(context.Background(), HandlerName))
		secondHTTP, err := p.httpClientForConfig(context.Background(), p.baseConfig())
		require.NoError(t, err)
		assert.NotSame(t, firstHTTP, secondHTTP)
		require.NoError(t, p.StopAuthHandler(context.Background(), HandlerName))

		// sanitizeControlChars strips C0, ESC, C1, bidi overrides, invalid UTF-8, normalizes whitespace, and caps length
		assert.Equal(t, "", sanitizeControlChars(""))
		assert.Equal(t, "bad [31mrederror", sanitizeControlChars("  bad\r\n\t\x1b[31mred\x00\u202e\u0085\u009b"+string([]byte{0xff})+"error  "))
		longInput := strings.Repeat("a", 600)
		assert.Len(t, sanitizeControlChars(longInput), 512)
	})
}
