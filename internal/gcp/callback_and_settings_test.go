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
	merged := map[string]any{
		"iss": "https://accounts.google.com",
		"aud": DefaultADCClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range claims {
		merged[k] = v
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload, _ := json.Marshal(merged)
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
	onDo     func(ctx context.Context, req *http.Request) (*http.Response, error)
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

func (b *blockingHTTPClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if b.onDo != nil {
		return b.onDo(ctx, req)
	}
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
							"aud":   clientID,
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

		badCIDRCfg, err := parseHandlerConfig([]byte(`{"httpClient":{"allowedPrivateCIDRs":["not-a-cidr"]}}`))
		require.NoError(t, err)
		_, err = p.httpClientForConfig(context.Background(), badCIDRCfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid allowedPrivateCIDRs")

		// Equivalent allowedPrivateCIDRs in different order share one cached client; trustProxyResolution partitions cache keys
		cidrCfgA, err := parseHandlerConfig([]byte(`{"httpClient":{"allowedPrivateCIDRs":["127.0.0.0/8","10.0.0.0/8"],"trustProxyResolution":true}}`))
		require.NoError(t, err)
		cidrCfgB, err := parseHandlerConfig([]byte(`{"httpClient":{"allowedPrivateCIDRs":["10.0.0.0/8","127.0.0.0/8"],"trustProxyResolution":true}}`))
		require.NoError(t, err)
		cidrCfgNoTrust, err := parseHandlerConfig([]byte(`{"httpClient":{"allowedPrivateCIDRs":["10.0.0.0/8","127.0.0.0/8"],"trustProxyResolution":false}}`))
		require.NoError(t, err)
		cidrClientA, err := p.httpClientForConfig(context.Background(), cidrCfgA)
		require.NoError(t, err)
		cidrClientB, err := p.httpClientForConfig(context.Background(), cidrCfgB)
		require.NoError(t, err)
		cidrClientNoTrust, err := p.httpClientForConfig(context.Background(), cidrCfgNoTrust)
		require.NoError(t, err)
		assert.Same(t, cidrClientA, cidrClientB)
		assert.NotSame(t, cidrClientA, cidrClientNoTrust)

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

	// 1. Uncached non-rotating 200 OK refresh probe must NOT mutate secrets/cache
	mockHTTP.AddResponse(http.StatusOK, TokenResponse{
		AccessToken: "probed-at",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})
	st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.True(t, st.Authenticated)
	assert.Equal(t, "stored-sa@proj.iam.gserviceaccount.com", st.ClientID)

	fake.mu.Lock()
	assert.Equal(t, before, fake.secrets, "GetStatus non-rotating 200 probe must not write cached tokens or mutate secrets")
	fake.mu.Unlock()

	// 1b. If Google rotates refresh_token during GetStatus probe, persist rotated refresh_token
	// safely so a one-time refresh grant is not lost, without populating the access-token cache.
	mockHTTP.AddResponse(http.StatusOK, TokenResponse{
		AccessToken:  "probed-at-rot",
		RefreshToken: "rotated-during-status-rt",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	})
	stRot, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.True(t, stRot.Authenticated)
	_, curRT, hasRT, err := p.inspectStoredMetadataAndRefresh(context.Background())
	require.NoError(t, err)
	require.True(t, hasRT)
	assert.Equal(t, "rotated-during-status-rt", curRT)

	fake.mu.Lock()
	afterRot := make(map[string]string, len(fake.secrets))
	for k, v := range fake.secrets {
		afterRot[k] = v
		assert.False(t, strings.HasPrefix(k, SecretKeyTokenPrefix), "GetStatus must not populate access-token cache")
	}
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
	assert.Equal(t, afterRot, fake.secrets, "GetStatus invalid_grant probe must not delete stored credentials")
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
		}, origMeta, "rt-1", DefaultADCClientID))

		rotMeta, rt, hasRT, err := p.inspectStoredMetadataAndRefresh(context.Background())
		require.NoError(t, err)
		require.True(t, hasRT)
		assert.Equal(t, "rt-2", rt)
		assert.Equal(t, "keep-proj", rotMeta.Project)
		assert.Equal(t, "keep-sa@proj.iam.gserviceaccount.com", rotMeta.ImpersonateServiceAccount)

		// Concurrent late rotation carrying superseded revision (same SessionID "sess-rot-1",
		// old RefreshTokenID/Hash from origMeta) must NOT overwrite rt-2!
		require.NoError(t, p.storeRotatedCredentials(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "late-at",
			RefreshToken: "late-rt",
		}, origMeta, "rt-1", DefaultADCClientID))
		afterLateMeta, afterLateRT, _, err := p.inspectStoredMetadataAndRefresh(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "rt-2", afterLateRT)
		assert.Equal(t, rotMeta.RefreshTokenID, afterLateMeta.RefreshTokenID)

		// Late invalid_grant carrying superseded revision (same SessionID "sess-rot-1",
		// old RefreshTokenID/Hash from origMeta) must NOT wipe the rotated session!
		p.logoutIfRefreshRevisionMatches(context.Background(), origMeta.SessionID, origMeta.RefreshTokenID, origMeta.RefreshTokenHash, "rt-1")
		_, stillRT, stillHasRT, err := p.inspectStoredMetadataAndRefresh(context.Background())
		require.NoError(t, err)
		require.True(t, stillHasRT)
		assert.Equal(t, "rt-2", stillRT)

		// Replace session with sess-rot-2; stale rotation for sess-rot-1 must be a no-op
		_, err = p.storeCredentialsWithClaims(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "at-b",
			RefreshToken: "rt-b",
		}, auth.FlowInteractive, []string{"openid"}, "sess-rot-2", DefaultADCClientID, &auth.Claims{Email: "b@example.com"})
		require.NoError(t, err)

		require.NoError(t, p.storeRotatedCredentials(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "stale-at",
			RefreshToken: "stale-rt",
		}, rotMeta, "rt-2", DefaultADCClientID))

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

func TestCredentialValidationAndSessionIsolation(t *testing.T) {
	t.Run("rejects ID tokens with wrong issuer, wrong audience, mismatched azp, missing sub, expired exp, future nbf, or invalid JWS across flows", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		badTokens := []struct {
			name   string
			claims map[string]any
		}{
			{
				name:   "wrong issuer",
				claims: map[string]any{"iss": "https://evil.example.com", "sub": "u1"},
			},
			{
				name:   "wrong scalar audience",
				claims: map[string]any{"aud": "other-client.apps.googleusercontent.com", "sub": "u1"},
			},
			{
				name:   "wrong array audience",
				claims: map[string]any{"aud": []string{"other-1", "other-2"}, "sub": "u1"},
			},
			{
				name:   "mismatched azp",
				claims: map[string]any{"azp": "other-azp.apps.googleusercontent.com", "sub": "u1"},
			},
			{
				name:   "missing subject",
				claims: map[string]any{"sub": "   "},
			},
			{
				name:   "expired exp",
				claims: map[string]any{"sub": "u1", "exp": time.Now().Add(-5 * time.Minute).Unix()},
			},
			{
				name:   "missing exp",
				claims: map[string]any{"sub": "u1", "exp": 0},
			},
			{
				name:   "future nbf",
				claims: map[string]any{"sub": "u1", "nbf": time.Now().Add(5 * time.Minute).Unix()},
			},
		}

		for _, tc := range badTokens {
			t.Run("interactive_"+tc.name, func(t *testing.T) {
				p, fake, mockHTTP := newTestPlugin(t)
				_, wantFailure := configureCustomCallbackPages(t, p)
				mockHTTP.AddResponse(http.StatusOK, TokenResponse{
					AccessToken:  "at",
					RefreshToken: "rt",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					IDToken:      makeTestIDToken(tc.claims),
				})

				statusCh := make(chan int, 1)
				bodyCh := make(chan string, 1)
				p.openBrowser = func(_ context.Context, authURL string) error {
					u, _ := url.Parse(authURL)
					redirect := u.Query().Get("redirect_uri")
					state := u.Query().Get("state")
					go func() {
						resp, err := http.Get(redirect + "/?code=IDTOK&state=" + url.QueryEscape(state)) //nolint:noctx
						if err != nil {
							statusCh <- 0
							bodyCh <- ""
							return
						}
						b, _ := io.ReadAll(resp.Body)
						_ = resp.Body.Close()
						statusCh <- resp.StatusCode
						bodyCh <- string(b)
					}()
					return nil
				}

				_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
				require.Error(t, err)
				assert.Equal(t, http.StatusServiceUnavailable, <-statusCh)
				assert.Equal(t, wantFailure, <-bodyCh)
				assert.Empty(t, fake.secrets)
			})

			t.Run("device_code_"+tc.name, func(t *testing.T) {
				p, fake, mockHTTP := newTestPlugin(t)
				p.config.ClientID = "dev-client"
				p.config.ClientSecret = "dev-secret"
				claims := make(map[string]any, len(tc.claims)+1)
				claims["aud"] = "dev-client"
				for k, v := range tc.claims {
					claims[k] = v
				}
				mockHTTP.AddResponse(http.StatusOK, DeviceCodeResponse{
					DeviceCode:      "dc",
					UserCode:        "UC",
					VerificationURL: "https://accounts.google.com/device",
					ExpiresIn:       300,
					Interval:        1,
				})
				mockHTTP.AddResponse(http.StatusOK, TokenResponse{
					AccessToken:  "at",
					RefreshToken: "rt",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					IDToken:      makeTestIDToken(claims),
				})

				_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowDeviceCode}, nil)
				require.Error(t, err)
				assert.Empty(t, fake.secrets)
			})
		}

		// Valid array audience containing client ID succeeds
		validArrToken := makeTestIDToken(map[string]any{
			"iss":   "accounts.google.com",
			"aud":   []string{"other-aud", DefaultADCClientID},
			"sub":   "arr-sub",
			"email": "arr@example.com",
		})
		claims, err := validateAndExtractIDTokenClaims(validArrToken, DefaultADCClientID, time.Now())
		require.NoError(t, err)
		assert.Equal(t, "arr-sub", claims.Subject)
	})

	t.Run("corrupt stored metadata or GetSecret error fails closed in GetToken instead of falling back to ambient gcloud_adc or GCE metadata", func(t *testing.T) {
		dir := t.TempDir()
		gcloudADCBytes, _ := json.Marshal(map[string]string{
			"type":          "authorized_user",
			"client_id":     "gcloud-cid",
			"client_secret": "gcloud-sec",
			"refresh_token": "gcloud-rt",
		})
		require.NoError(t, os.WriteFile(filepath.Join(dir, "application_default_credentials.json"), gcloudADCBytes, 0o600))
		t.Setenv(EnvCloudSDKConfig, dir)
		t.Setenv(EnvGoogleApplicationCredentials, "")
		t.Setenv(EnvGoogleExternalAccount, "")

		metaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(MetadataTokenResponse{AccessToken: "ambient-gce-at", TokenType: "Bearer", ExpiresIn: 3600})
		}))
		t.Cleanup(metaSrv.Close)
		t.Setenv(EnvGCEMetadataHost, metaSrv.Listener.Addr().String())

		p, fake, mockHTTP := newTestPlugin(t)
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{AccessToken: "ambient-gcloud-at", TokenType: "Bearer", ExpiresIn: 3600})

		// 1. Corrupt metadata JSON
		fake.secrets[SecretKeyMetadata] = "{corrupt-json"
		_, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "cloud-platform"})
		require.ErrorIs(t, err, ErrNotAuthenticated)

		// 2. GetSecret error on metadata
		delete(fake.secrets, SecretKeyMetadata)
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyMetadata {
				return errors.New("secret store unavailable")
			}
			return nil
		}
		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "cloud-platform"})
		require.ErrorIs(t, err, ErrNotAuthenticated)
	})

	t.Run("DetectAvailableFlows returns error on broken explicit credential files instead of advertising lower-priority flows", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		p, _, _ := newTestPlugin(t)
		saCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			"serviceAccountKeyFile": json.RawMessage(`"/missing/sa.json"`),
		})
		_, err := p.DetectAvailableFlows(saCtx, HandlerName)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service account credentials error")

		wifCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			"externalAccountFile": json.RawMessage(`"/missing/wif.json"`),
		})
		_, err = p.DetectAvailableFlows(wifCtx, HandlerName)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "workload identity credentials error")
	})

	t.Run("impersonation isolates per-RPC SA override from stored interactive session cache and metadata", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		dir := t.TempDir()
		saFile := filepath.Join(dir, "override-sa.json")
		saBytes, _ := json.Marshal(ServiceAccountKey{
			Type:         "service_account",
			ProjectID:    "proj",
			PrivateKeyID: "kid",
			PrivateKey:   generateTestRSAKey(t),
			ClientEmail:  "override-sa@proj.iam.gserviceaccount.com",
			ClientID:     "override-cid",
		})
		require.NoError(t, os.WriteFile(saFile, saBytes, 0o600))

		p, _, _ := newTestPlugin(t)
		targetSA := "shared-target@proj.iam.gserviceaccount.com"
		p.config.ImpersonateServiceAccount = targetSA

		var iamCalls atomic.Int32
		p.httpClient = &blockingHTTPClient{
			onDo: func(_ context.Context, _ *http.Request) (*http.Response, error) {
				n := iamCalls.Add(1)
				return jsonHTTPResponse(http.StatusOK, ImpersonationResponse{
					AccessToken: fmt.Sprintf("imp-token-%d", n),
					ExpireTime:  time.Now().Add(time.Hour).Format(time.RFC3339),
				}), nil
			},
			onPost: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
				if data.Get("grant_type") == "authorization_code" {
					return jsonHTTPResponse(http.StatusOK, TokenResponse{
						AccessToken:  "interactive-src-at",
						RefreshToken: "interactive-src-rt",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						IDToken:      makeTestIDToken(map[string]any{"sub": "int-u", "email": "int@example.com"}),
					}), nil
				}
				return jsonHTTPResponse(http.StatusOK, TokenResponse{
					AccessToken: "sa-src-at",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}), nil
			},
		}
		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "INT-IMP")
			return nil
		}

		// 1. Interactive login + impersonated GetToken caches imp-token-1 under interactive session
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)
		intTok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "https://www.googleapis.com/auth/cloud-platform"})
		require.NoError(t, err)
		assert.Equal(t, "imp-token-1", intTok.AccessToken)
		assert.Equal(t, auth.FlowInteractive, intTok.Flow)
		assert.NotEmpty(t, intTok.SessionID)

		// 2. Per-RPC serviceAccountKeyFile override targeting the SAME targetSA must NOT reuse imp-token-1 or interactive SessionID!
		saOverrideSettings := map[string]json.RawMessage{
			"serviceAccountKeyFile":     json.RawMessage(fmt.Sprintf("%q", saFile)),
			"impersonateServiceAccount": json.RawMessage(fmt.Sprintf("%q", targetSA)),
		}
		saTok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:    "https://www.googleapis.com/auth/cloud-platform",
			Settings: saOverrideSettings,
		})
		require.NoError(t, err)
		assert.Equal(t, "imp-token-2", saTok.AccessToken)
		assert.Equal(t, auth.FlowServicePrincipal, saTok.Flow)
		assert.Empty(t, saTok.SessionID)
		assert.Equal(t, int32(2), iamCalls.Load())
	})

	t.Run("replacement login without refresh_token marks NoRefreshToken so failed legacy DeleteSecret cannot leak old refresh token", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		p, fake, mockHTTP := newTestPlugin(t)
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at",
			RefreshToken: "alice-legacy-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      makeTestIDToken(map[string]any{"sub": "alice", "email": "alice@example.com"}),
		})
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "bob-no-rt-at",
			TokenType:   "Bearer",
			ExpiresIn:   600,
			IDToken:     makeTestIDToken(map[string]any{"sub": "bob", "email": "bob@example.com"}),
		})
		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "REPL-NO-RT")
			return nil
		}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)
		assert.Equal(t, "alice-legacy-rt", fake.secrets[SecretKeyRefreshToken])

		// Fail DeleteSecret on legacy SecretKeyRefreshToken during Bob's refresh-token-less login
		fake.mu.Lock()
		fake.deleteSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyRefreshToken {
				return errors.New("delete failed")
			}
			return nil
		}
		fake.mu.Unlock()

		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)

		// Even though SecretKeyRefreshToken still holds "alice-legacy-rt", Bob's metadata has
		// NoRefreshToken: true so forceRefresh must NOT mint with Alice's refresh token!
		_, hasRT, err := func() (*TokenMetadata, bool, error) {
			m, _, hr, e := p.inspectStoredMetadataAndRefresh(context.Background())
			return m, hr, e
		}()
		require.NoError(t, err)
		assert.False(t, hasRT)

		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:        "https://www.googleapis.com/auth/cloud-platform",
			ForceRefresh: true,
		})
		require.ErrorIs(t, err, ErrNotAuthenticated)
	})

	t.Run("two per-RPC externalAccountFile configs sharing an audience do not share cached WIF tokens", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		dir := t.TempDir()
		sharedAud := "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/shared/providers/p"

		writeWIF := func(prefix, assertion string) string {
			subj := filepath.Join(dir, prefix+"-token")
			require.NoError(t, os.WriteFile(subj, []byte(assertion), 0o600))
			cfgPath := filepath.Join(dir, prefix+"-wif.json")
			b, _ := json.Marshal(ExternalAccountConfig{
				Type:             "external_account",
				Audience:         sharedAud,
				SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
				CredentialSource: CredentialSource{File: subj},
			})
			require.NoError(t, os.WriteFile(cfgPath, b, 0o600))
			return cfgPath
		}
		wifA := writeWIF("a", "assertion-A")
		wifB := writeWIF("b", "assertion-B")

		p, _, _ := newTestPlugin(t)
		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, STSTokenResponse{
					AccessToken: "sts-" + data.Get("subject_token"),
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}), nil
			},
		}

		tokA, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:    "https://www.googleapis.com/auth/cloud-platform",
			Settings: map[string]json.RawMessage{"externalAccountFile": json.RawMessage(fmt.Sprintf("%q", wifA))},
		})
		require.NoError(t, err)
		assert.Equal(t, "sts-assertion-A", tokA.AccessToken)

		tokB, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:    "https://www.googleapis.com/auth/cloud-platform",
			Settings: map[string]json.RawMessage{"externalAccountFile": json.RawMessage(fmt.Sprintf("%q", wifB))},
		})
		require.NoError(t, err)
		assert.Equal(t, "sts-assertion-B", tokB.AccessToken)
	})

	t.Run("Logout guards sessionless snapshots and metadata reread failures; gcloud_adc and metadata Login propagate persistence failures", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		// 1. Legacy sessionless snapshot replaced during revocation is NOT deleted,
		// and metadata reread failure after revocation aborts deletion with an error.
		p, fake, _ := newTestPlugin(t)
		revokeEntered := make(chan struct{})
		releaseRevoke := make(chan struct{})
		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, endpoint string, _ url.Values) (*http.Response, error) {
				if endpoint == revokeEndpoint {
					select {
					case <-revokeEntered:
					default:
						close(revokeEntered)
					}
					<-releaseRevoke
					return jsonHTTPResponse(http.StatusOK, map[string]string{}), nil
				}
				return jsonHTTPResponse(http.StatusOK, TokenResponse{
					AccessToken:  "repl-at",
					RefreshToken: "repl-rt",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					IDToken:      makeTestIDToken(map[string]any{"sub": "repl", "email": "repl@example.com"}),
				}), nil
			},
		}

		// Legacy metadata with NO SessionID
		fake.secrets[SecretKeyMetadata] = `{"flow":"interactive"}`
		fake.secrets[SecretKeyRefreshToken] = "legacy-rt"

		logoutDone := make(chan error, 1)
		go func() {
			logoutDone <- p.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{})
		}()
		<-revokeEntered

		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "REPL-LEGACY")
			return nil
		}
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)
		close(releaseRevoke)
		require.NoError(t, <-logoutDone)

		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, st.Authenticated)
		assert.Equal(t, "repl@example.com", st.Claims.Email)

		// Metadata reread error after revocation aborts deletion
		var metaReads atomic.Int32
		fake.mu.Lock()
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyMetadata && metaReads.Add(1) >= 3 {
				return errors.New("reread failure")
			}
			return nil
		}
		fake.mu.Unlock()
		err = p.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{})
		require.Error(t, err)
		fake.mu.Lock()
		fake.getSecretFunc = nil
		fake.mu.Unlock()
		assert.NotEmpty(t, fake.secrets[SecretKeyMetadata])

		// 2. gcloud_adc and metadata Login fail when metadata persistence fails
		dir := t.TempDir()
		gcloudADCBytes, _ := json.Marshal(map[string]string{
			"type":          "authorized_user",
			"client_id":     "gcloud-cid",
			"client_secret": "gcloud-sec",
			"refresh_token": "gcloud-rt",
		})
		require.NoError(t, os.WriteFile(filepath.Join(dir, "application_default_credentials.json"), gcloudADCBytes, 0o600))
		t.Setenv(EnvCloudSDKConfig, dir)

		metaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/token") {
				_ = json.NewEncoder(w).Encode(MetadataTokenResponse{AccessToken: "m-at", TokenType: "Bearer", ExpiresIn: 3600})
				return
			}
			_, _ = w.Write([]byte("meta@proj.iam.gserviceaccount.com"))
		}))
		t.Cleanup(metaSrv.Close)
		t.Setenv(EnvGCEMetadataHost, metaSrv.Listener.Addr().String())

		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, endpoint string, _ url.Values) (*http.Response, error) {
				if endpoint == stsEndpoint {
					return jsonHTTPResponse(http.StatusOK, STSTokenResponse{
						AccessToken: "wi-at",
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					}), nil
				}
				return jsonHTTPResponse(http.StatusOK, TokenResponse{
					AccessToken: "flow-at",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}), nil
			},
		}

		fake.mu.Lock()
		fake.setSecretKeyErr = map[string]error{SecretKeyMetadata: errors.New("disk full")}
		fake.mu.Unlock()

		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowGcloudADC}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to store metadata")

		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowMetadata}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to store metadata")

		// service_principal and workload_identity Login also propagate metadata persistence failures
		saPath := filepath.Join(dir, "sa-persist.json")
		saBytes, _ := json.Marshal(ServiceAccountKey{
			Type:         "service_account",
			ProjectID:    "proj",
			PrivateKeyID: "kid",
			PrivateKey:   generateTestRSAKey(t),
			ClientEmail:  "sa-persist@proj.iam.gserviceaccount.com",
			ClientID:     "cid",
		})
		require.NoError(t, os.WriteFile(saPath, saBytes, 0o600))
		subjPath := filepath.Join(dir, "wif-subj")
		require.NoError(t, os.WriteFile(subjPath, []byte("subj-jwt"), 0o600))
		wifPath := filepath.Join(dir, "wif-persist.json")
		wifBytes, _ := json.Marshal(ExternalAccountConfig{
			Type:             "external_account",
			Audience:         "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/pr",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
			CredentialSource: CredentialSource{File: subjPath},
		})
		require.NoError(t, os.WriteFile(wifPath, wifBytes, 0o600))

		saCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			"serviceAccountKeyFile": json.RawMessage(fmt.Sprintf("%q", saPath)),
		})
		_, err = p.Login(saCtx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowServicePrincipal}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to store metadata")

		wifCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			"externalAccountFile": json.RawMessage(fmt.Sprintf("%q", wifPath)),
		})
		_, err = p.Login(wifCtx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowWorkloadIdentity}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to store metadata")
	})

	t.Run("rejects malformed JWS headers, alg none, 5-part JWE, and invalid gcloud_adc ID tokens; PurgeExpiredTokens holds exclusive profileLock", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		validPayload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iss":"https://accounts.google.com","aud":%q,"sub":"u1","exp":%d}`, DefaultADCClientID, time.Now().Add(time.Hour).Unix())))
		_, err := validateAndExtractIDTokenClaims(noneHeader+"."+validPayload+".sig", DefaultADCClientID, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported alg")

		rsHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
		_, err = validateAndExtractIDTokenClaims(rsHeader+"."+validPayload+".", DefaultADCClientID, time.Now())
		require.Error(t, err)
		_, err = validateAndExtractIDTokenClaims(rsHeader+"."+validPayload+".c.d.e", DefaultADCClientID, time.Now())
		require.Error(t, err)

		// gcloudADCLogin rejects invalid IDToken in token response
		dir := t.TempDir()
		gcloudADCBytes, _ := json.Marshal(map[string]string{
			"type":          "authorized_user",
			"client_id":     "gcloud-cid",
			"client_secret": "gcloud-sec",
			"refresh_token": "gcloud-rt",
		})
		require.NoError(t, os.WriteFile(filepath.Join(dir, "application_default_credentials.json"), gcloudADCBytes, 0o600))
		t.Setenv(EnvCloudSDKConfig, dir)

		p, fake, mockHTTP := newTestPlugin(t)
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "gcloud-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IDToken:     makeTestIDToken(map[string]any{"iss": "https://wrong.issuer", "aud": "gcloud-cid", "sub": "u1"}),
		})
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowGcloudADC}, nil)
		require.Error(t, err)
		assert.Empty(t, fake.secrets)

		// PurgeExpiredTokens holds exclusive profileLock so a concurrent cacheTokenForSession
		// cannot race between PurgeExpiredTokens's GetSecret and DeleteSecret.
		cacheKey := buildCacheKey(auth.FlowServicePrincipal, fingerprintHash("sa@proj.iam.gserviceaccount.com"), "cloud-platform")
		fullKey := SecretKeyTokenPrefix + cacheKey
		require.NoError(t, cacheSetWithPrefix(context.Background(), p.hostClient(context.Background()), SecretKeyTokenPrefix, cacheKey, &auth.Token{
			AccessToken: "expired-at",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(-time.Minute),
			Scope:       "cloud-platform",
			Flow:        auth.FlowServicePrincipal,
		}))

		purgeEntered := make(chan struct{})
		releasePurge := make(chan struct{})
		fake.mu.Lock()
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if name == fullKey {
				select {
				case <-purgeEntered:
				default:
					close(purgeEntered)
					<-releasePurge
				}
			}
			return nil
		}
		fake.mu.Unlock()

		purgeDone := make(chan error, 1)
		go func() {
			_, pErr := p.PurgeExpiredTokens(context.Background(), HandlerName)
			purgeDone <- pErr
		}()

		<-purgeEntered

		writeDone := make(chan struct{})
		go func() {
			p.cacheTokenForSession(context.Background(), cacheKey, &auth.Token{
				AccessToken: "fresh-at",
				TokenType:   "Bearer",
				ExpiresAt:   time.Now().Add(time.Hour),
				Scope:       "cloud-platform",
				Flow:        auth.FlowServicePrincipal,
			})
			close(writeDone)
		}()

		// Because PurgeExpiredTokens holds mu.Lock(), cacheTokenForSession (mu.RLock())
		// must wait until PurgeExpiredTokens finishes deleting the expired entry!
		select {
		case <-writeDone:
			t.Fatal("cacheTokenForSession must block while PurgeExpiredTokens holds profile write lock")
		case <-time.After(30 * time.Millisecond):
		}

		close(releasePurge)
		require.NoError(t, <-purgeDone)
		<-writeDone

		fake.mu.Lock()
		fake.getSecretFunc = nil
		fake.mu.Unlock()

		surviving, err := cacheGetWithPrefix(context.Background(), p.hostClient(context.Background()), SecretKeyTokenPrefix, cacheKey)
		require.NoError(t, err)
		require.NotNil(t, surviving)
		assert.Equal(t, "fresh-at", surviving.AccessToken)
	})
}

func TestADCLogin_UserinfoFailurePreservesPriorSessionAndServesFailureHTML(t *testing.T) {
	clearAmbientGCPEnv(t)

	aliceJWT := makeTestIDToken(map[string]any{"sub": "alice-sub", "email": "alice@example.com"})

	for _, tc := range []struct {
		name        string
		userinfoRes *http.Response
		userinfoErr error
		wantErr     string
	}{
		{
			name:        "userinfo HTTP 500 error",
			userinfoRes: jsonHTTPResponse(http.StatusInternalServerError, map[string]string{"error": "backend_down"}),
			wantErr:     "failed to fetch userinfo claims",
		},
		{
			name:        "userinfo network error",
			userinfoErr: errors.New("userinfo connection reset"),
			wantErr:     "failed to fetch userinfo claims",
		},
		{
			name:        "userinfo missing sub claim",
			userinfoRes: jsonHTTPResponse(http.StatusOK, map[string]string{"email": "nosub@example.com"}),
			wantErr:     "missing sub claim",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _ := newTestPlugin(t)
			wantSuccess, wantFailure := configureCustomCallbackPages(t, p)

			var callNum atomic.Int32
			p.httpClient = &blockingHTTPClient{
				onPost: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
					if data.Get("grant_type") == "refresh_token" {
						return jsonHTTPResponse(http.StatusOK, TokenResponse{
							AccessToken: "alice-refreshed-at",
							TokenType:   "Bearer",
							ExpiresIn:   3600,
						}), nil
					}
					if callNum.Add(1) == 1 {
						return jsonHTTPResponse(http.StatusOK, TokenResponse{
							AccessToken:  "alice-at",
							RefreshToken: "alice-rt",
							TokenType:    "Bearer",
							ExpiresIn:    3600,
							IDToken:      aliceJWT,
						}), nil
					}
					// Replacement login omits IDToken so adcLogin falls back to userinfo.
					return jsonHTTPResponse(http.StatusOK, TokenResponse{
						AccessToken:  "bob-at",
						RefreshToken: "bob-rt",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
					}), nil
				},
			}

			// First login succeeds for Alice.
			p.openBrowser = func(_ context.Context, authURL string) error {
				completeLoopbackCallback(t, authURL, "ALICE-CODE")
				return nil
			}
			_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
			require.NoError(t, err)

			// Override Get for userinfo failure on second login.
			origPost := p.httpClient.(*blockingHTTPClient).onPost
			p.httpClient = &userinfoMockClient{
				onPost: origPost,
				onGet: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
					if tc.userinfoErr != nil {
						return nil, tc.userinfoErr
					}
					return tc.userinfoRes, nil
				},
			}

			statusCh := make(chan int, 1)
			bodyCh := make(chan string, 1)
			p.openBrowser = func(_ context.Context, authURL string) error {
				u, _ := url.Parse(authURL)
				go func() {
					resp, getErr := http.Get(u.Query().Get("redirect_uri") + "/?code=BOB-CODE&state=" + url.QueryEscape(u.Query().Get("state"))) //nolint:noctx
					if getErr != nil {
						statusCh <- 0
						bodyCh <- ""
						return
					}
					b, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					statusCh <- resp.StatusCode
					bodyCh <- string(b)
				}()
				return nil
			}

			_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Equal(t, http.StatusServiceUnavailable, <-statusCh)
			body := <-bodyCh
			assert.Equal(t, wantFailure, body)
			assert.NotEqual(t, wantSuccess, body)

			// Alice's session and refresh token must remain intact.
			st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
			require.NoError(t, err)
			require.True(t, st.Authenticated)
			assert.Equal(t, "alice@example.com", st.Claims.Email)

			tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
				Scope:        "openid",
				ForceRefresh: true,
			})
			require.NoError(t, err)
			assert.Equal(t, "alice-refreshed-at", tok.AccessToken)
		})
	}
}

type userinfoMockClient struct {
	onPost func(ctx context.Context, endpoint string, data url.Values) (*http.Response, error)
	onGet  func(ctx context.Context, endpoint string, headers map[string]string) (*http.Response, error)
	onDo   func(ctx context.Context, req *http.Request) (*http.Response, error)
}

func (u *userinfoMockClient) PostForm(ctx context.Context, endpoint string, data url.Values) (*http.Response, error) {
	return u.onPost(ctx, endpoint, data)
}

func (u *userinfoMockClient) Get(ctx context.Context, endpoint string, headers map[string]string) (*http.Response, error) {
	return u.onGet(ctx, endpoint, headers)
}

func (u *userinfoMockClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if u.onDo != nil {
		return u.onDo(ctx, req)
	}
	return jsonHTTPResponse(http.StatusInternalServerError, map[string]string{"error": "unexpected Do"}), nil
}

func TestConcurrentRefreshSerializationAndRotationPersistence(t *testing.T) {
	t.Run("serializes concurrent GetToken and GetStatus refreshes across single-use grant rotation without holding profileLock during HTTP", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		p, _, _ := newTestPlugin(t)
		_, err := p.storeCredentialsWithClaims(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "seed-at",
			RefreshToken: "rt-gen-1",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      makeTestIDToken(map[string]any{"sub": "u-conc", "email": "conc@example.com"}),
		}, auth.FlowInteractive, []string{"openid"}, "sess-conc", DefaultADCClientID, nil)
		require.NoError(t, err)

		firstRefreshEntered := make(chan struct{})
		releaseFirstRefresh := make(chan struct{})
		var usedMu sync.Mutex
		usedGrants := map[string]bool{}
		var postCalls atomic.Int32

		// Simulate a single-use rotating OAuth server: any duplicate submission of an
		// already-consumed refresh_token returns 400 invalid_grant immediately (which
		// would arrive BEFORE the delayed first rotation response if refreshes raced).
		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
				n := postCalls.Add(1)
				rt := data.Get("refresh_token")

				usedMu.Lock()
				alreadyUsed := usedGrants[rt]
				usedGrants[rt] = true
				usedMu.Unlock()

				if alreadyUsed {
					return jsonHTTPResponse(http.StatusBadRequest, TokenErrorResponse{
						Error:            "invalid_grant",
						ErrorDescription: "refresh token already consumed",
					}), nil
				}

				if n == 1 {
					close(firstRefreshEntered)
					<-releaseFirstRefresh
				}

				nextGen := fmt.Sprintf("rt-gen-%d", n+1)
				return jsonHTTPResponse(http.StatusOK, TokenResponse{
					AccessToken:  fmt.Sprintf("at-gen-%d", n),
					RefreshToken: nextGen,
					TokenType:    "Bearer",
					ExpiresIn:    3600,
				}), nil
			},
		}

		// Launch concurrent GetToken (cache miss), GetToken (ForceRefresh), and GetStatus.
		tok1Ch := make(chan *sdkplugin.TokenResponse, 1)
		err1Ch := make(chan error, 1)
		tok2Ch := make(chan *sdkplugin.TokenResponse, 1)
		err2Ch := make(chan error, 1)
		statusCh := make(chan *auth.Status, 1)
		statusErrCh := make(chan error, 1)

		go func() {
			r, e := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "openid"})
			tok1Ch <- r
			err1Ch <- e
		}()

		<-firstRefreshEntered

		// Give concurrent callers time to queue on refreshLock while first HTTP call is held.
		go func() {
			r, e := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "openid", ForceRefresh: true})
			tok2Ch <- r
			err2Ch <- e
		}()
		go func() {
			s, e := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
			statusCh <- s
			statusErrCh <- e
		}()

		// Verify profileLock is NOT held during the blocked HTTP call: ListCachedTokens
		// (which acquires profileLock.RLock) must return immediately without blocking.
		listDone := make(chan error, 1)
		go func() {
			_, lErr := p.ListCachedTokens(context.Background(), HandlerName)
			listDone <- lErr
		}()
		select {
		case lErr := <-listDone:
			require.NoError(t, lErr)
		case <-time.After(500 * time.Millisecond):
			t.Fatal("ListCachedTokens blocked while HTTP refresh was in flight; profileLock must not be held across HTTP")
		}

		time.Sleep(25 * time.Millisecond)
		close(releaseFirstRefresh)

		require.NoError(t, <-err1Ch)
		require.NoError(t, <-err2Ch)
		require.NoError(t, <-statusErrCh)
		assert.NotEmpty(t, (<-tok1Ch).AccessToken)
		assert.NotEmpty(t, (<-tok2Ch).AccessToken)
		assert.True(t, (<-statusCh).Authenticated)

		// Session must still be intact and backed by the latest rotated refresh token.
		_, curRT, hasRT, err := p.inspectStoredMetadataAndRefresh(context.Background())
		require.NoError(t, err)
		require.True(t, hasRT)
		assert.Equal(t, fmt.Sprintf("rt-gen-%d", postCalls.Load()+1), curRT)
	})

	t.Run("GetStatus holding refreshLock first rotates grant without caching access token and queued GetStatus reloads rotated grant", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		p, _, _ := newTestPlugin(t)
		_, err := p.storeCredentialsWithClaims(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "seed-at",
			RefreshToken: "rt-status-1",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      makeTestIDToken(map[string]any{"sub": "u-st-conc", "email": "stconc@example.com"}),
		}, auth.FlowInteractive, []string{"openid"}, "sess-st-conc", DefaultADCClientID, nil)
		require.NoError(t, err)

		firstProbeEntered := make(chan struct{})
		releaseFirstProbe := make(chan struct{})
		var usedMu sync.Mutex
		usedGrants := map[string]bool{}
		var postCalls atomic.Int32

		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
				n := postCalls.Add(1)
				rt := data.Get("refresh_token")

				usedMu.Lock()
				alreadyUsed := usedGrants[rt]
				usedGrants[rt] = true
				usedMu.Unlock()

				if alreadyUsed {
					return jsonHTTPResponse(http.StatusBadRequest, TokenErrorResponse{
						Error:            "invalid_grant",
						ErrorDescription: "refresh token already consumed",
					}), nil
				}

				if n == 1 {
					close(firstProbeEntered)
					<-releaseFirstProbe
				}

				return jsonHTTPResponse(http.StatusOK, TokenResponse{
					AccessToken:  fmt.Sprintf("status-at-%d", n),
					RefreshToken: fmt.Sprintf("rt-status-%d", n+1),
					TokenType:    "Bearer",
					ExpiresIn:    3600,
				}), nil
			},
		}

		st1Ch := make(chan *auth.Status, 1)
		st2Ch := make(chan *auth.Status, 1)
		tokCh := make(chan *sdkplugin.TokenResponse, 1)
		errCh := make(chan error, 3)

		go func() {
			s, e := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
			st1Ch <- s
			errCh <- e
		}()

		<-firstProbeEntered

		// Queue a second GetStatus while st1 holds refreshLock; because neither st1 nor
		// st2 populates the access-token cache, st2 MUST reload rt-status-2 inside
		// refreshLock and issue a second PostForm instead of reusing rt-status-1.
		go func() {
			s, e := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
			st2Ch <- s
			errCh <- e
		}()

		time.Sleep(25 * time.Millisecond)
		close(releaseFirstProbe)

		for range 2 {
			require.NoError(t, <-errCh)
		}
		assert.True(t, (<-st1Ch).Authenticated)
		assert.True(t, (<-st2Ch).Authenticated)
		assert.Equal(t, int32(2), postCalls.Load())

		// Subsequent ForceRefresh GetToken reloads rt-status-3 seamlessly.
		tokResp, tokErr := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "openid", ForceRefresh: true})
		require.NoError(t, tokErr)
		assert.NotEmpty(t, tokResp.AccessToken)
		assert.Equal(t, int32(3), postCalls.Load())
		_ = tokCh
	})

	t.Run("mintToken propagates rotated refresh token persistence failure without caching access token", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		p, fake, mockHTTP := newTestPlugin(t)
		_, err := p.storeCredentialsWithClaims(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "init-at",
			RefreshToken: "orig-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      makeTestIDToken(map[string]any{"sub": "u-rot-err", "email": "roterr@example.com"}),
		}, auth.FlowInteractive, []string{"openid"}, "sess-rot-err", DefaultADCClientID, nil)
		require.NoError(t, err)

		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "rotated-at-must-not-cache",
			RefreshToken: "rotated-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})

		fake.mu.Lock()
		fake.setSecretErr = errors.New("secret store write failed")
		fake.mu.Unlock()

		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:        "openid",
			ForceRefresh: true,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "persisting rotated refresh token")

		fake.mu.Lock()
		for k := range fake.secrets {
			assert.False(t, strings.HasPrefix(k, SecretKeyTokenPrefix), "failed rotation must not cache access token")
		}
		fake.mu.Unlock()
	})
}

func TestGcloudADC_AccountSwitchCacheIsolation(t *testing.T) {
	clearAmbientGCPEnv(t)

	adcDir := t.TempDir()
	adcPath := filepath.Join(adcDir, "application_default_credentials.json")
	t.Setenv(EnvCloudSDKConfig, adcDir)

	writeADC := func(rt string) {
		b, err := json.Marshal(GcloudADCCredentials{
			ClientID:     DefaultADCClientID,
			ClientSecret: DefaultADCClientSecret,
			RefreshToken: rt,
			Type:         "authorized_user",
		})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(adcPath, b, 0o600))
	}

	p, _, _ := newTestPlugin(t)
	var refreshCalls, iamCalls atomic.Int32
	p.httpClient = &blockingHTTPClient{
		onPost: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
			refreshCalls.Add(1)
			rt := data.Get("refresh_token")
			if rt == "rt-revoked-B" {
				return jsonHTTPResponse(http.StatusBadRequest, TokenErrorResponse{
					Error:            "invalid_grant",
					ErrorDescription: "account B revoked",
				}), nil
			}
			return jsonHTTPResponse(http.StatusOK, TokenResponse{
				AccessToken: "access-for-" + rt,
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				Scope:       defaultGcloudADCScope,
			}), nil
		},
		onDo: func(_ context.Context, req *http.Request) (*http.Response, error) {
			iamCalls.Add(1)
			srcAuth := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
			return jsonHTTPResponse(http.StatusOK, ImpersonationResponse{
				AccessToken: "imp-via-" + srcAuth,
				ExpireTime:  time.Now().Add(time.Hour).Format(time.RFC3339),
			}), nil
		},
	}

	// 1. Account A login + token + impersonated token populate caches under DefaultADCClientID + hash(rt-A).
	writeADC("rt-account-A")
	_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowGcloudADC}, nil)
	require.NoError(t, err)

	tokA, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: defaultGcloudADCScope})
	require.NoError(t, err)
	assert.Equal(t, "access-for-rt-account-A", tokA.AccessToken)

	impSettings := map[string]json.RawMessage{
		"impersonateServiceAccount": json.RawMessage(`"target@proj.iam.gserviceaccount.com"`),
	}
	impA, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
		Scope:    defaultGcloudADCScope,
		Settings: impSettings,
	})
	require.NoError(t, err)
	assert.Equal(t, "imp-via-access-for-rt-account-A", impA.AccessToken)

	// 2. Switch gcloud ADC file to Account B sharing the same DefaultADCClientID:
	// neither direct GetToken nor impersonation may reuse Account A's cached token.
	writeADC("rt-account-B")
	tokB, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: defaultGcloudADCScope})
	require.NoError(t, err)
	assert.Equal(t, "access-for-rt-account-B", tokB.AccessToken)

	impB, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
		Scope:    defaultGcloudADCScope,
		Settings: impSettings,
	})
	require.NoError(t, err)
	assert.Equal(t, "imp-via-access-for-rt-account-B", impB.AccessToken)
	assert.Equal(t, int32(2), iamCalls.Load())

	// 3. Switch gcloud ADC file to revoked Account B: GetStatus must NOT pass via Account A's cache entry.
	writeADC("rt-revoked-B")
	stB, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.False(t, stB.Authenticated)
	assert.Contains(t, stB.Reason, "invalid")
}

func TestStoreCredentials_LostMetadataAckReconciliationAndBoundedLegacyMirror(t *testing.T) {
	clearAmbientGCPEnv(t)

	aliceJWT := makeTestIDToken(map[string]any{"sub": "alice", "email": "alice@example.com"})
	bobJWT := makeTestIDToken(map[string]any{"sub": "bob", "email": "bob@example.com"})

	t.Run("lost SetSecret ack after host commits metadata restores prior session before deleting new revision", func(t *testing.T) {
		p, fake, mockHTTP := newTestPlugin(t)
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at",
			RefreshToken: "alice-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "bob-at",
			RefreshToken: "bob-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      bobJWT,
		})
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "alice-refreshed-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "ACK-CODE")
			return nil
		}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)

		// Fault injection: host writes metadata to its store, then the gRPC ack fails once.
		var faultFired atomic.Bool
		fake.mu.Lock()
		fake.setSecretFunc = func(_ context.Context, name, value string) error {
			if name == SecretKeyMetadata && !faultFired.Swap(true) {
				fake.mu.Lock()
				fake.secrets[name] = value
				fake.mu.Unlock()
				return errors.New("rpc error: code = DeadlineExceeded desc = lost SetSecret reply")
			}
			return nil
		}
		fake.mu.Unlock()

		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.Error(t, err)

		// Alice's session must be restored and consistent, and Bob's revision cleaned up.
		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		require.True(t, st.Authenticated)
		assert.Equal(t, "alice@example.com", st.Claims.Email)

		tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "openid", ForceRefresh: true})
		require.NoError(t, err)
		assert.Equal(t, "alice-refreshed-at", tok.AccessToken)

		fake.mu.Lock()
		for k, v := range fake.secrets {
			if strings.HasPrefix(k, SecretKeyRefreshToken+".") {
				assert.NotEqual(t, "bob-rt", v, "unreferenced revision must be deleted after rollback")
			}
		}
		fake.mu.Unlock()
	})

	t.Run("lost SetSecret ack when rollback also fails preserves referenced refresh token revision so store stays consistent", func(t *testing.T) {
		p, fake, mockHTTP := newTestPlugin(t)
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "bob-at",
			RefreshToken: "bob-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      bobJWT,
		})
		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "bob-refreshed-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "ACK-NO-ROLLBACK")
			return nil
		}

		// First SetSecret(metadata) commits then fails ack; subsequent DeleteSecret(metadata) fails too.
		var metaSetCalls atomic.Int32
		fake.mu.Lock()
		fake.setSecretFunc = func(_ context.Context, name, value string) error {
			if name == SecretKeyMetadata && metaSetCalls.Add(1) == 1 {
				fake.mu.Lock()
				fake.secrets[name] = value
				fake.mu.Unlock()
				return errors.New("lost SetSecret ack")
			}
			return nil
		}
		fake.deleteSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyMetadata {
				return errors.New("rollback delete failed")
			}
			return nil
		}
		fake.mu.Unlock()

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.Error(t, err)

		fake.mu.Lock()
		fake.setSecretFunc = nil
		fake.deleteSecretFunc = nil
		fake.mu.Unlock()

		// Because metadataKey still references bob's revID, bob's versioned refresh token
		// must NOT have been deleted (no errInconsistentSession).
		meta, rt, hasRT, err := p.inspectStoredMetadataAndRefresh(context.Background())
		require.NoError(t, err)
		require.True(t, hasRT)
		assert.Equal(t, "bob-rt", rt)
		assert.Equal(t, "bob@example.com", meta.Claims.Email)
	})

	t.Run("lost SetSecret ack during refresh-token rotation reconciles committed rotation without rolling back to consumed grant", func(t *testing.T) {
		p, fake, _ := newTestPlugin(t)
		_, err := p.storeCredentialsWithClaims(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "at-1",
			RefreshToken: "consumed-rt-1",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		}, auth.FlowInteractive, []string{"openid"}, "sess-rot-ack", DefaultADCClientID, nil)
		require.NoError(t, err)

		origMeta, err := p.loadMetadata(context.Background())
		require.NoError(t, err)

		var faultFired atomic.Bool
		fake.mu.Lock()
		fake.setSecretFunc = func(_ context.Context, name, value string) error {
			if name == SecretKeyMetadata && !faultFired.Swap(true) {
				fake.mu.Lock()
				fake.secrets[name] = value
				fake.mu.Unlock()
				return errors.New("lost SetSecret ack on rotation")
			}
			return nil
		}
		fake.mu.Unlock()

		err = p.storeRotatedCredentials(context.Background(), DefaultConfig(), &TokenResponse{
			AccessToken:  "at-2",
			RefreshToken: "new-rt-2",
		}, origMeta, "consumed-rt-1", DefaultADCClientID)
		require.NoError(t, err)

		_, curRT, hasRT, err := p.inspectStoredMetadataAndRefresh(context.Background())
		require.NoError(t, err)
		require.True(t, hasRT)
		assert.Equal(t, "new-rt-2", curRT)
	})

	t.Run("stalled legacy-mirror SetSecret uses bounded cleanup context so Login and browser callback settle promptly", func(t *testing.T) {
		p, fake, mockHTTP := newTestPlugin(t)
		p.cleanupTimeout = 40 * time.Millisecond
		wantSuccess, _ := configureCustomCallbackPages(t, p)

		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "mirror-at",
			RefreshToken: "mirror-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})

		mirrorDeadlineCh := make(chan bool, 1)
		fake.mu.Lock()
		fake.setSecretFunc = func(ctx context.Context, name, _ string) error {
			if name == SecretKeyRefreshToken {
				_, hasDeadline := ctx.Deadline()
				select {
				case mirrorDeadlineCh <- hasDeadline:
				default:
				}
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		}
		fake.mu.Unlock()

		browserStatusCh := make(chan int, 1)
		browserBodyCh := make(chan string, 1)
		p.openBrowser = func(_ context.Context, authURL string) error {
			u, _ := url.Parse(authURL)
			go func() {
				resp, getErr := http.Get(u.Query().Get("redirect_uri") + "/?code=MIRROR-CODE&state=" + url.QueryEscape(u.Query().Get("state"))) //nolint:noctx
				if getErr != nil {
					browserStatusCh <- 0
					browserBodyCh <- ""
					return
				}
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				browserStatusCh <- resp.StatusCode
				browserBodyCh <- string(b)
			}()
			return nil
		}

		started := time.Now()
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)
		assert.Less(t, time.Since(started), 2*time.Second)
		assert.True(t, <-mirrorDeadlineCh)
		assert.Equal(t, http.StatusOK, <-browserStatusCh)
		assert.Equal(t, wantSuccess, <-browserBodyCh)
	})
}

func TestGetStatus_NoRefreshTokenUserSessions(t *testing.T) {
	clearAmbientGCPEnv(t)

	for _, flow := range []auth.Flow{auth.FlowInteractive, auth.FlowDeviceCode} {
		t.Run(string(flow), func(t *testing.T) {
			p, fake, mockHTTP := newTestPlugin(t)
			p.config.ClientID = "nort-client"
			p.config.ClientSecret = "nort-secret"

			idTok := makeTestIDToken(map[string]any{
				"aud":   "nort-client",
				"sub":   "nort-sub",
				"email": "nort@example.com",
			})

			if flow == auth.FlowInteractive {
				mockHTTP.AddResponse(http.StatusOK, TokenResponse{
					AccessToken: "nort-access-token",
					TokenType:   "Bearer",
					ExpiresIn:   900,
					IDToken:     idTok,
				})
				p.openBrowser = func(_ context.Context, authURL string) error {
					completeLoopbackCallback(t, authURL, "NORT-STATUS")
					return nil
				}
			} else {
				mockHTTP.AddResponse(http.StatusOK, DeviceCodeResponse{
					DeviceCode:      "dc-nort",
					UserCode:        "UC-NORT",
					VerificationURL: "https://accounts.google.com/device",
					ExpiresIn:       300,
					Interval:        1,
				})
				mockHTTP.AddResponse(http.StatusOK, TokenResponse{
					AccessToken: "nort-access-token",
					TokenType:   "Bearer",
					ExpiresIn:   900,
					IDToken:     idTok,
				})
			}

			loginResp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: flow}, nil)
			require.NoError(t, err)

			// 1. While cached access token is usable, GetStatus returns Authenticated=true and reports its expiry without HTTP calls.
			reqsBefore := len(mockHTTP.GetRequests())
			stValid, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
			require.NoError(t, err)
			require.True(t, stValid.Authenticated)
			assert.False(t, stValid.ExpiresAt.IsZero())
			assert.WithinDuration(t, loginResp.ExpiresAt, stValid.ExpiresAt, 2*time.Second)
			assert.Len(t, mockHTTP.GetRequests(), reqsBefore, "GetStatus must not mint tokens for NoRefreshToken sessions")

			// 2. When cached access token has less than DefaultMinValidFor remaining (or is expired),
			// both GetStatus and GetToken treat the session as unauthenticated.
			cacheKey := buildCacheKey(flow, fingerprintHash("nort-client"), "")
			expiredBytes, _ := json.Marshal(tokenCacheEntry{
				AccessToken: "nort-access-token",
				TokenType:   "Bearer",
				ExpiresAt:   time.Now().Add(-time.Minute),
				CachedAt:    time.Now().Add(-15 * time.Minute),
				Flow:        flow,
				SessionID:   func() string { m, _ := p.loadMetadata(context.Background()); return m.SessionID }(),
			})
			fake.mu.Lock()
			fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(expiredBytes)
			fake.mu.Unlock()

			stExpired, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
			require.NoError(t, err)
			assert.False(t, stExpired.Authenticated)
			assert.True(t, stExpired.ExpiresAt.IsZero())
			assert.Equal(t, "expired or revoked", stExpired.Reason)

			_, tokErr := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "openid"})
			require.ErrorIs(t, tokErr, ErrNotAuthenticated)

			// 3. After PurgeExpiredTokens removes the expired cached access token, GetStatus stays unauthenticated.
			purged, err := p.PurgeExpiredTokens(context.Background(), HandlerName)
			require.NoError(t, err)
			assert.Equal(t, 1, purged)

			stPurged, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
			require.NoError(t, err)
			assert.False(t, stPurged.Authenticated)
			assert.Equal(t, "expired or revoked", stPurged.Reason)
		})
	}
}

func TestImpersonation_SourceIdentityCapturedBeforeExchange(t *testing.T) {
	const targetSA = "target@proj.iam.gserviceaccount.com"
	const testScope = "https://www.googleapis.com/auth/cloud-platform"

	t.Run("gcloud ADC file switch during source exchange does not poison second account impersonation cache", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		gcloudDir := t.TempDir()
		t.Setenv(EnvCloudSDKConfig, gcloudDir)
		adcPath := filepath.Join(gcloudDir, "application_default_credentials.json")

		writeADC := func(clientID, refreshToken string) {
			raw, err := json.Marshal(GcloudADCCredentials{
				Type:         "authorized_user",
				ClientID:     clientID,
				ClientSecret: "secret-" + clientID,
				RefreshToken: refreshToken,
			})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(adcPath, raw, 0o600))
		}
		writeADC("adc-client-a", "rt-account-a")

		p, _, _ := newTestPlugin(t)
		p.config.ImpersonateServiceAccount = targetSA

		var impCalls atomic.Int32
		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
				rt := data.Get("refresh_token")
				if rt == "rt-account-a" {
					// Switch gcloud's ADC file to account B while A's source token exchange is in flight.
					writeADC("adc-client-a", "rt-account-b")
					return jsonHTTPResponse(http.StatusOK, TokenResponse{
						AccessToken: "source-at-a",
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					}), nil
				}
				return jsonHTTPResponse(http.StatusOK, TokenResponse{
					AccessToken: "source-at-b",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}), nil
			},
			onDo: func(_ context.Context, req *http.Request) (*http.Response, error) {
				impCalls.Add(1)
				authz := req.Header.Get("Authorization")
				if authz == "Bearer source-at-a" {
					return jsonHTTPResponse(http.StatusOK, ImpersonationResponse{
						AccessToken: "imp-token-from-a",
						ExpireTime:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
					}), nil
				}
				return jsonHTTPResponse(http.StatusOK, ImpersonationResponse{
					AccessToken: "imp-token-from-b",
					ExpireTime:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				}), nil
			},
		}

		tokA, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: testScope})
		require.NoError(t, err)
		assert.Equal(t, "imp-token-from-a", tokA.AccessToken)

		tokB, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: testScope})
		require.NoError(t, err)
		assert.Equal(t, "imp-token-from-b", tokB.AccessToken, "account B must not reuse an impersonated token minted by account A")
		assert.Equal(t, int32(2), impCalls.Load())
	})

	t.Run("service account key file switch during source exchange does not poison second SA impersonation cache", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		dir := t.TempDir()
		saPath := filepath.Join(dir, "sa.json")
		privPEM := generateTestRSAKey(t)
		writeSA := func(email string) {
			raw, err := json.Marshal(ServiceAccountKey{
				Type:         "service_account",
				ProjectID:    "proj",
				PrivateKeyID: "kid",
				PrivateKey:   privPEM,
				ClientEmail:  email,
				ClientID:     email,
			})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(saPath, raw, 0o600))
		}
		writeSA("sa-a@proj.iam.gserviceaccount.com")

		p, _, _ := newTestPlugin(t)
		p.config.ServiceAccountKeyFile = saPath
		p.config.ImpersonateServiceAccount = targetSA

		var saMints atomic.Int32
		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				n := saMints.Add(1)
				if n == 1 {
					writeSA("sa-b@proj.iam.gserviceaccount.com")
					return jsonHTTPResponse(http.StatusOK, TokenResponse{
						AccessToken: "sa-source-a",
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					}), nil
				}
				return jsonHTTPResponse(http.StatusOK, TokenResponse{
					AccessToken: "sa-source-b",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}), nil
			},
			onDo: func(_ context.Context, req *http.Request) (*http.Response, error) {
				if req.Header.Get("Authorization") == "Bearer sa-source-a" {
					return jsonHTTPResponse(http.StatusOK, ImpersonationResponse{
						AccessToken: "imp-sa-a",
						ExpireTime:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
					}), nil
				}
				return jsonHTTPResponse(http.StatusOK, ImpersonationResponse{
					AccessToken: "imp-sa-b",
					ExpireTime:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				}), nil
			},
		}

		tokA, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: testScope})
		require.NoError(t, err)
		assert.Equal(t, "imp-sa-a", tokA.AccessToken)

		tokB, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: testScope})
		require.NoError(t, err)
		assert.Equal(t, "imp-sa-b", tokB.AccessToken)
	})

	t.Run("workload identity config switch during STS exchange does not poison second pool impersonation cache", func(t *testing.T) {
		clearAmbientGCPEnv(t)

		dir := t.TempDir()
		subjFile := filepath.Join(dir, "subj.jwt")
		require.NoError(t, os.WriteFile(subjFile, []byte("jwt-token"), 0o600))
		wifPath := filepath.Join(dir, "wif.json")
		writeWIF := func(audience string) {
			raw, err := json.Marshal(ExternalAccountConfig{
				Type:             "external_account",
				Audience:         audience,
				SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
				CredentialSource: CredentialSource{File: subjFile},
			})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(wifPath, raw, 0o600))
		}
		writeWIF("//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool-a/providers/p")

		p, _, _ := newTestPlugin(t)
		p.config.ExternalAccountFile = wifPath
		p.config.ImpersonateServiceAccount = targetSA

		p.httpClient = &blockingHTTPClient{
			onPost: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
				if strings.Contains(data.Get("audience"), "pool-a") {
					writeWIF("//iam.googleapis.com/projects/2/locations/global/workloadIdentityPools/pool-b/providers/p")
					return jsonHTTPResponse(http.StatusOK, STSTokenResponse{
						AccessToken: "wi-source-a",
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					}), nil
				}
				return jsonHTTPResponse(http.StatusOK, STSTokenResponse{
					AccessToken: "wi-source-b",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}), nil
			},
			onDo: func(_ context.Context, req *http.Request) (*http.Response, error) {
				if req.Header.Get("Authorization") == "Bearer wi-source-a" {
					return jsonHTTPResponse(http.StatusOK, ImpersonationResponse{
						AccessToken: "imp-wi-a",
						ExpireTime:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
					}), nil
				}
				return jsonHTTPResponse(http.StatusOK, ImpersonationResponse{
					AccessToken: "imp-wi-b",
					ExpireTime:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				}), nil
			},
		}

		tokA, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: testScope})
		require.NoError(t, err)
		assert.Equal(t, "imp-wi-a", tokA.AccessToken)

		tokB, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: testScope})
		require.NoError(t, err)
		assert.Equal(t, "imp-wi-b", tokB.AccessToken)
	})
}

func TestTransactionalLoginCommits_SeedSnapshotAndCancellation(t *testing.T) {
	clearAmbientGCPEnv(t)

	aliceJWT := makeTestIDToken(map[string]any{"sub": "alice-sub", "email": "alice@example.com"})
	bobJWT := makeTestIDToken(map[string]any{"sub": "bob-sub", "email": "bob@example.com"})

	t.Run("refresh-token-less interactive and device-code logins fail and preserve prior session and cache when seed write fails", func(t *testing.T) {
		for _, lostAck := range []bool{false, true} {
			for _, flow := range []auth.Flow{auth.FlowInteractive, auth.FlowDeviceCode} {
				t.Run(fmt.Sprintf("%s_lostAck=%v", flow, lostAck), func(t *testing.T) {
					p, fake, mockHTTP := newTestPlugin(t)
					_, wantFailure := configureCustomCallbackPages(t, p)

					// Establish Alice's session + cached access token + an extra cached entry.
					mockHTTP.AddResponse(http.StatusOK, TokenResponse{
						AccessToken:  "alice-seeded-at",
						RefreshToken: "alice-rt",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						IDToken:      aliceJWT,
					})
					p.openBrowser = func(_ context.Context, authURL string) error {
						completeLoopbackCallback(t, authURL, "ALICE-INIT")
						return nil
					}
					_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
					require.NoError(t, err)

					aliceMeta, err := p.loadMetadata(context.Background())
					require.NoError(t, err)
					extraCacheKey := SecretKeyTokenPrefix + "extra-impersonated-entry"
					extraBytes, _ := json.Marshal(tokenCacheEntry{
						AccessToken: "alice-extra-at",
						TokenType:   "Bearer",
						ExpiresAt:   time.Now().Add(time.Hour),
						CachedAt:    time.Now(),
						Flow:        auth.FlowInteractive,
						SessionID:   aliceMeta.SessionID,
					})
					fake.mu.Lock()
					fake.secrets[extraCacheKey] = string(extraBytes)
					fake.mu.Unlock()

					targetSeedKey := SecretKeyTokenPrefix + buildCacheKey(flow, fingerprintHash(DefaultADCClientID), "")
					var failedOnce atomic.Bool
					fake.mu.Lock()
					fake.setSecretFunc = func(_ context.Context, name, value string) error {
						if name == targetSeedKey && failedOnce.CompareAndSwap(false, true) {
							if lostAck {
								fake.mu.Lock()
								fake.secrets[name] = value
								fake.mu.Unlock()
							}
							return errors.New("seed storage quota exceeded")
						}
						return nil
					}
					fake.mu.Unlock()

					browserStatusCh := make(chan int, 1)
					browserBodyCh := make(chan string, 1)
					if flow == auth.FlowInteractive {
						mockHTTP.AddResponse(http.StatusOK, TokenResponse{
							AccessToken: "bob-nort-at",
							TokenType:   "Bearer",
							ExpiresIn:   900,
							IDToken:     bobJWT,
						})
						p.openBrowser = func(_ context.Context, authURL string) error {
							u, _ := url.Parse(authURL)
							go func() {
								resp, getErr := http.Get(u.Query().Get("redirect_uri") + "/?code=BOB-NORT&state=" + url.QueryEscape(u.Query().Get("state"))) //nolint:noctx
								if getErr != nil {
									browserStatusCh <- 0
									browserBodyCh <- ""
									return
								}
								b, _ := io.ReadAll(resp.Body)
								_ = resp.Body.Close()
								browserStatusCh <- resp.StatusCode
								browserBodyCh <- string(b)
							}()
							return nil
						}
					} else {
						mockHTTP.AddResponse(http.StatusOK, DeviceCodeResponse{
							DeviceCode:      "dc-bob",
							UserCode:        "UC-BOB",
							VerificationURL: "https://accounts.google.com/device",
							ExpiresIn:       300,
							Interval:        1,
						})
						mockHTTP.AddResponse(http.StatusOK, TokenResponse{
							AccessToken: "bob-nort-at",
							TokenType:   "Bearer",
							ExpiresIn:   900,
							IDToken:     bobJWT,
						})
					}

					_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: flow}, nil)
					require.Error(t, err)
					assert.Contains(t, err.Error(), "failed to seed initial access token")
					if flow == auth.FlowInteractive {
						assert.Equal(t, http.StatusServiceUnavailable, <-browserStatusCh)
						assert.Equal(t, wantFailure, <-browserBodyCh)
					}

					fake.mu.Lock()
					fake.setSecretFunc = nil
					_, hasExtra := fake.secrets[extraCacheKey]
					fake.mu.Unlock()
					assert.True(t, hasExtra, "prior cached tokens must not be cleared when replacement login fails")

					// Alice's session and cached access token remain active without extra HTTP calls.
					reqsBefore := len(mockHTTP.GetRequests())
					st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
					require.NoError(t, err)
					require.True(t, st.Authenticated)
					assert.Equal(t, "alice@example.com", st.Claims.Email)

					tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "openid"})
					require.NoError(t, err)
					assert.Equal(t, "alice-seeded-at", tok.AccessToken)
					assert.Len(t, mockHTTP.GetRequests(), reqsBefore)
				})
			}
		}
	})

	t.Run("snapshot GetSecret failure aborts before writing credentials in both storeCredentialsAndSeedToken and storeMetadataAndSeedToken", func(t *testing.T) {
		p, fake, mockHTTP := newTestPlugin(t)

		mockHTTP.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at",
			RefreshToken: "alice-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})
		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "ALICE-SNAP")
			return nil
		}
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)

		var writesAttempted atomic.Int32
		fake.mu.Lock()
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyMetadata {
				return errors.New("secret backend unavailable")
			}
			return nil
		}
		fake.setSecretFunc = func(_ context.Context, name, value string) error {
			writesAttempted.Add(1)
			fake.mu.Lock()
			fake.secrets[name] = value
			fake.mu.Unlock()
			return errors.New("lost ack write")
		}
		fake.mu.Unlock()

		_, err = p.storeCredentialsAndSeedToken(
			context.Background(),
			DefaultConfig(),
			&TokenResponse{AccessToken: "bob-at", RefreshToken: "bob-rt", ExpiresIn: 3600, IDToken: bobJWT},
			auth.FlowInteractive,
			[]string{"openid"},
			"",
			DefaultADCClientID,
			nil,
			buildCacheKey(auth.FlowInteractive, fingerprintHash(DefaultADCClientID), ""),
			&auth.Token{AccessToken: "bob-at", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour), Flow: auth.FlowInteractive},
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading previous session metadata")
		assert.Equal(t, int32(0), writesAttempted.Load(), "must abort before writing any secrets when snapshot read fails")

		_, err = p.storeMetadataAndSeedToken(
			context.Background(),
			&auth.Claims{Issuer: "https://accounts.google.com", Subject: "sa@proj.iam.gserviceaccount.com", Email: "sa@proj.iam.gserviceaccount.com"},
			auth.FlowServicePrincipal,
			[]string{"cloud-platform"},
			buildCacheKey(auth.FlowServicePrincipal, fingerprintHash("sa@proj.iam.gserviceaccount.com"), "cloud-platform"),
			&auth.Token{AccessToken: "sa-at", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour), Flow: auth.FlowServicePrincipal},
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading previous session metadata")
		assert.Equal(t, int32(0), writesAttempted.Load(), "storeMetadataAndSeedToken must abort before writing any secrets when snapshot read fails")

		fake.mu.Lock()
		fake.getSecretFunc = nil
		fake.setSecretFunc = nil
		fake.mu.Unlock()

		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		require.True(t, st.Authenticated)
		assert.Equal(t, "alice@example.com", st.Claims.Email)
	})

	t.Run("cancellation during detached legacy-mirror write settles 503 FailureHTML, returns ErrUserCancelled, and rolls back to prior session", func(t *testing.T) {
		p, fake, mockHTTP := newTestPlugin(t)
		_, wantFailure := configureCustomCallbackPages(t, p)

		// 1. Alice logs in first.
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
			AccessToken: "alice-at-refreshed",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})

		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "ALICE-OK")
			return nil
		}
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)

		// 2. Bob starts Login; cancel Bob's context right inside the detached legacy-mirror SetSecret!
		loginCtx, cancelLogin := context.WithCancel(context.Background())
		defer cancelLogin()

		var cancelledInMirror atomic.Bool
		fake.mu.Lock()
		fake.setSecretFunc = func(_ context.Context, name, _ string) error {
			if name == SecretKeyRefreshToken && cancelledInMirror.CompareAndSwap(false, true) {
				cancelLogin()
			}
			return nil
		}
		fake.mu.Unlock()

		browserStatusCh := make(chan int, 1)
		browserBodyCh := make(chan string, 1)
		p.openBrowser = func(_ context.Context, authURL string) error {
			u, _ := url.Parse(authURL)
			go func() {
				resp, getErr := http.Get(u.Query().Get("redirect_uri") + "/?code=BOB-CANCEL-MIRROR&state=" + url.QueryEscape(u.Query().Get("state"))) //nolint:noctx
				if getErr != nil {
					browserStatusCh <- 0
					browserBodyCh <- ""
					return
				}
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				browserStatusCh <- resp.StatusCode
				browserBodyCh <- string(b)
			}()
			return nil
		}

		_, err = p.Login(loginCtx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.ErrorIs(t, err, ErrUserCancelled)
		assert.True(t, cancelledInMirror.Load())
		assert.Equal(t, http.StatusServiceUnavailable, <-browserStatusCh)
		assert.Equal(t, wantFailure, <-browserBodyCh)

		fake.mu.Lock()
		fake.setSecretFunc = nil
		legacyVal := fake.secrets[SecretKeyRefreshToken]
		var versionedKeys []string
		for k, v := range fake.secrets {
			if strings.HasPrefix(k, SecretKeyRefreshToken+".") {
				versionedKeys = append(versionedKeys, v)
			}
		}
		fake.mu.Unlock()
		assert.Equal(t, "alice-rt", legacyVal, "legacy refresh token mirror must roll back to Alice's token")
		assert.Equal(t, []string{"alice-rt"}, versionedKeys, "Bob's unreferenced versioned refresh token must be cleaned up while keeping Alice's")

		// Alice's session, cached access token, and refresh token all remain intact.
		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		require.True(t, st.Authenticated)
		assert.Equal(t, "alice@example.com", st.Claims.Email)

		cachedTok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "openid"})
		require.NoError(t, err)
		assert.Equal(t, "alice-at-1", cachedTok.AccessToken)

		refreshedTok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:        "openid",
			ForceRefresh: true,
		})
		require.NoError(t, err)
		assert.Equal(t, "alice-at-refreshed", refreshedTok.AccessToken)
		assert.Equal(t, "alice-rt", mockHTTP.GetRequests()[2].Data.Get("refresh_token"))
	})

	t.Run("refresh-token-less interactive and device-code logins reject missing zero negative or sub-threshold expires_in before writing", func(t *testing.T) {
		for _, expiresIn := range []int{0, -60, 60} {
			for _, flow := range []auth.Flow{auth.FlowInteractive, auth.FlowDeviceCode} {
				t.Run(fmt.Sprintf("%s_expiresIn=%d", flow, expiresIn), func(t *testing.T) {
					p, fake, mockHTTP := newTestPlugin(t)
					_, wantFailure := configureCustomCallbackPages(t, p)

					// Establish Alice's session first.
					mockHTTP.AddResponse(http.StatusOK, TokenResponse{
						AccessToken:  "alice-valid-at",
						RefreshToken: "alice-rt",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						IDToken:      aliceJWT,
					})
					p.openBrowser = func(_ context.Context, authURL string) error {
						completeLoopbackCallback(t, authURL, "ALICE-EXP-INIT")
						return nil
					}
					_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
					require.NoError(t, err)

					var writesAttempted atomic.Int32
					fake.mu.Lock()
					fake.setSecretFunc = func(_ context.Context, _, _ string) error {
						writesAttempted.Add(1)
						return nil
					}
					fake.mu.Unlock()

					browserStatusCh := make(chan int, 1)
					browserBodyCh := make(chan string, 1)
					if flow == auth.FlowInteractive {
						mockHTTP.AddResponse(http.StatusOK, TokenResponse{
							AccessToken: "bob-expired-at",
							TokenType:   "Bearer",
							ExpiresIn:   expiresIn,
							IDToken:     bobJWT,
						})
						p.openBrowser = func(_ context.Context, authURL string) error {
							u, _ := url.Parse(authURL)
							go func() {
								resp, getErr := http.Get(u.Query().Get("redirect_uri") + "/?code=BOB-EXP&state=" + url.QueryEscape(u.Query().Get("state"))) //nolint:noctx
								if getErr != nil {
									browserStatusCh <- 0
									browserBodyCh <- ""
									return
								}
								b, _ := io.ReadAll(resp.Body)
								_ = resp.Body.Close()
								browserStatusCh <- resp.StatusCode
								browserBodyCh <- string(b)
							}()
							return nil
						}
					} else {
						mockHTTP.AddResponse(http.StatusOK, DeviceCodeResponse{
							DeviceCode:      "dc-exp",
							UserCode:        "UC-EXP",
							VerificationURL: "https://accounts.google.com/device",
							ExpiresIn:       300,
							Interval:        1,
						})
						mockHTTP.AddResponse(http.StatusOK, TokenResponse{
							AccessToken: "bob-expired-at",
							TokenType:   "Bearer",
							ExpiresIn:   expiresIn,
							IDToken:     bobJWT,
						})
					}

					_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: flow}, nil)
					require.Error(t, err)
					assert.Contains(t, err.Error(), "initial access token lifetime does not satisfy minimum validity")
					assert.Equal(t, int32(0), writesAttempted.Load(), "must reject invalid initial lifetime before any secret writes")
					if flow == auth.FlowInteractive {
						assert.Equal(t, http.StatusServiceUnavailable, <-browserStatusCh)
						assert.Equal(t, wantFailure, <-browserBodyCh)
					}

					st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
					require.NoError(t, err)
					require.True(t, st.Authenticated)
					assert.Equal(t, "alice@example.com", st.Claims.Email)
				})
			}
		}
	})

	t.Run("panic during credential staging rolls back to prior session, settles 503 FailureHTML, and preserves panic across both staging branches", func(t *testing.T) {
		seedKey := SecretKeyTokenPrefix + buildCacheKey(auth.FlowInteractive, fingerprintHash(DefaultADCClientID), "")
		cases := []struct {
			name        string
			withRefresh bool
			panicKey    string
		}{
			{
				name:        "with_refresh_panic_after_metadata_on_legacy_mirror",
				withRefresh: true,
				panicKey:    SecretKeyRefreshToken,
			},
			{
				name:        "with_refresh_panic_after_access_token_seed",
				withRefresh: true,
				panicKey:    seedKey,
			},
			{
				name:        "no_refresh_panic_after_access_token_seed",
				withRefresh: false,
				panicKey:    seedKey,
			},
			{
				name:        "no_refresh_panic_after_metadata_commit",
				withRefresh: false,
				panicKey:    SecretKeyMetadata,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				p, fake, mockHTTP := newTestPlugin(t)
				_, wantFailure := configureCustomCallbackPages(t, p)

				mockHTTP.AddResponse(http.StatusOK, TokenResponse{
					AccessToken:  "alice-panic-at-1",
					RefreshToken: "alice-panic-rt",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					IDToken:      aliceJWT,
				})
				p.openBrowser = func(_ context.Context, authURL string) error {
					completeLoopbackCallback(t, authURL, "ALICE-PANIC-BASE")
					return nil
				}
				_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
				require.NoError(t, err)

				bobResp := TokenResponse{
					AccessToken: "bob-panic-at",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
					IDToken:     bobJWT,
				}
				if tc.withRefresh {
					bobResp.RefreshToken = "bob-panic-rt"
				}
				mockHTTP.AddResponse(http.StatusOK, bobResp)
				mockHTTP.AddResponse(http.StatusOK, TokenResponse{
					AccessToken: "alice-panic-at-refreshed",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				})

				var panickedOnce atomic.Bool
				fake.mu.Lock()
				fake.setSecretFunc = func(_ context.Context, name, value string) error {
					if name == tc.panicKey && panickedOnce.CompareAndSwap(false, true) {
						fake.mu.Lock()
						fake.secrets[name] = value
						fake.mu.Unlock()
						panic("simulated staging panic")
					}
					return nil
				}
				fake.mu.Unlock()

				browserStatusCh := make(chan int, 1)
				browserBodyCh := make(chan string, 1)
				p.openBrowser = func(_ context.Context, authURL string) error {
					u, _ := url.Parse(authURL)
					go func() {
						resp, getErr := http.Get(u.Query().Get("redirect_uri") + "/?code=BOB-PANIC-STAGE&state=" + url.QueryEscape(u.Query().Get("state"))) //nolint:noctx
						if getErr != nil {
							browserStatusCh <- 0
							browserBodyCh <- ""
							return
						}
						b, _ := io.ReadAll(resp.Body)
						_ = resp.Body.Close()
						browserStatusCh <- resp.StatusCode
						browserBodyCh <- string(b)
					}()
					return nil
				}

				assert.PanicsWithValue(t, "simulated staging panic", func() {
					_, _ = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
				})
				assert.True(t, panickedOnce.Load())
				assert.Equal(t, http.StatusServiceUnavailable, <-browserStatusCh)
				assert.Equal(t, wantFailure, <-browserBodyCh)

				fake.mu.Lock()
				fake.setSecretFunc = nil
				legacyVal := fake.secrets[SecretKeyRefreshToken]
				var versionedVals []string
				for k, v := range fake.secrets {
					if strings.HasPrefix(k, SecretKeyRefreshToken+".") {
						versionedVals = append(versionedVals, v)
					}
				}
				fake.mu.Unlock()
				assert.Equal(t, "alice-panic-rt", legacyVal)
				assert.Equal(t, []string{"alice-panic-rt"}, versionedVals)

				st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
				require.NoError(t, err)
				require.True(t, st.Authenticated)
				assert.Equal(t, "alice@example.com", st.Claims.Email)

				cachedTok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "openid"})
				require.NoError(t, err)
				assert.Equal(t, "alice-panic-at-1", cachedTok.AccessToken)

				refreshedTok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
					Scope:        "openid",
					ForceRefresh: true,
				})
				require.NoError(t, err)
				assert.Equal(t, "alice-panic-at-refreshed", refreshedTok.AccessToken)
				assert.Equal(t, "alice-panic-rt", mockHTTP.GetRequests()[2].Data.Get("refresh_token"))
			})
		}
	})
}

type closableClientStub struct {
	closed atomic.Int32
}

func (c *closableClientStub) Close() error {
	c.closed.Add(1)
	return nil
}

func TestBoundedClientCache_CloseAllRejectsAndClosesInFlightBuilders(t *testing.T) {
	cache := newBoundedClientCache[string, *closableClientStub](4)

	existing := &closableClientStub{}
	gotExisting, ok := cache.GetOrCreate("existing", func() *closableClientStub {
		return existing
	})
	require.True(t, ok)
	assert.Same(t, existing, gotExisting)
	assert.Equal(t, 1, cache.Len())

	inBuild := make(chan struct{})
	releaseBuild := make(chan struct{})
	pendingCandidate := &closableClientStub{}

	type getResult struct {
		val *closableClientStub
		ok  bool
	}
	resCh := make(chan getResult, 1)
	go func() {
		v, createdOK := cache.GetOrCreate("pending", func() *closableClientStub {
			close(inBuild)
			<-releaseBuild
			return pendingCandidate
		})
		resCh <- getResult{val: v, ok: createdOK}
	}()

	<-inBuild
	cache.CloseAll()
	assert.Equal(t, int32(1), existing.closed.Load(), "CloseAll must close existing cached entries immediately")
	assert.Equal(t, 0, cache.Len())

	// Unpause the pending builder after CloseAll has retired the cache.
	close(releaseBuild)
	res := <-resCh
	assert.False(t, res.ok, "in-flight builder finishing after CloseAll must be rejected")
	assert.Nil(t, res.val)
	assert.Equal(t, int32(1), pendingCandidate.closed.Load(), "in-flight candidate must be closed rather than leaked")
	assert.Equal(t, 0, cache.Len(), "retired cache must remain empty")

	// Terminal closure: subsequent GetOrCreate calls neither invoke build nor insert.
	var postCloseBuilds atomic.Int32
	postVal, postOK := cache.GetOrCreate("after-close", func() *closableClientStub {
		postCloseBuilds.Add(1)
		return &closableClientStub{}
	})
	assert.False(t, postOK)
	assert.Nil(t, postVal)
	assert.Equal(t, int32(0), postCloseBuilds.Load())
	assert.Equal(t, 0, cache.Len())
}
