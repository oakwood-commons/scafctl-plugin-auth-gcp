package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugintest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oakwood-commons/scafctl-plugin-auth-gcp/internal/clock"
)

// newTestPlugin creates a Plugin with fake host service and mock HTTP client.
func newTestPlugin(t *testing.T) (*Plugin, *fakeHostService, *MockHTTPClient) {
	t.Helper()
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)
	mockHTTP := NewMockHTTPClient()

	p := &Plugin{
		config:           DefaultConfig(),
		httpClient:       mockHTTP,
		clock:            clock.Mock{},
		cachedHostClient: hostClient,
		openBrowser:      func(_ context.Context, _ string) error { return nil },
		cfg:              sdkplugin.ProviderConfig{BinaryName: "testcli"},
	}

	return p, fake, mockHTTP
}

func TestGetAuthHandlers(t *testing.T) {
	p := &Plugin{}
	handlers, err := p.GetAuthHandlers(context.Background())
	require.NoError(t, err)
	require.Len(t, handlers, 1)
	assert.Equal(t, HandlerName, handlers[0].Name)
	assert.Equal(t, HandlerDisplayName, handlers[0].DisplayName)
	assert.Len(t, handlers[0].Flows, 6)
	assert.Equal(t, []auth.Capability{
		auth.CapScopesOnLogin,
		auth.CapScopesOnTokenRequest,
		auth.CapFederatedToken,
		auth.CapCallbackPort,
		auth.CapFlowOverride,
	}, handlers[0].Capabilities)
}

func TestConfigureAuthHandler(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		p := &Plugin{}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "mycli",
			Settings: map[string]json.RawMessage{
				HandlerName: json.RawMessage(`{"project": "my-project", "impersonateServiceAccount": "sa@project.iam.gserviceaccount.com"}`),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "my-project", p.config.Project)
		assert.Equal(t, "sa@project.iam.gserviceaccount.com", p.config.ImpersonateServiceAccount)
		assert.Equal(t, "mycli", p.cfg.BinaryName)
	})

	t.Run("unknown handler", func(t *testing.T) {
		p := &Plugin{}
		err := p.ConfigureAuthHandler(context.Background(), "unknown", sdkplugin.ProviderConfig{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")
	})

	t.Run("invalid config JSON", func(t *testing.T) {
		p := &Plugin{}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			Settings: map[string]json.RawMessage{
				HandlerName: json.RawMessage(`{invalid}`),
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse")
	})

	t.Run("invalid impersonation config", func(t *testing.T) {
		p := &Plugin{}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			Settings: map[string]json.RawMessage{
				HandlerName: json.RawMessage(`{"impersonateServiceAccount": "ab"}`),
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "impersonateServiceAccount")
	})

	t.Run("default scopes when no config", func(t *testing.T) {
		p := &Plugin{}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{})
		require.NoError(t, err)
		assert.Equal(t, DefaultConfig().DefaultScopes, p.config.DefaultScopes)
	})
}

func TestLogin_UnknownHandler(t *testing.T) {
	p := &Plugin{}
	_, err := p.Login(context.Background(), "unknown", sdkplugin.LoginRequest{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown handler")
}

func TestLogout(t *testing.T) {
	t.Run("known handler", func(t *testing.T) {
		p, _, _ := newTestPlugin(t)
		err := p.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{})
		require.NoError(t, err)
	})

	t.Run("unknown handler", func(t *testing.T) {
		p := &Plugin{}
		err := p.Logout(context.Background(), "unknown", sdkplugin.LogoutRequest{})
		assert.Error(t, err)
	})
}

func TestGetStatus_NotAuthenticated(t *testing.T) {
	p, _, _ := newTestPlugin(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
	t.Setenv("CLOUDSDK_CONFIG", t.TempDir())
	t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")
	status, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.False(t, status.Authenticated)
}

func TestGetStatus_WithMetadata(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	metadata := &TokenMetadata{
		Claims: &auth.Claims{
			Issuer:  "https://accounts.google.com",
			Subject: "user@example.com",
			Email:   "user@example.com",
		},
		Flow:           auth.FlowInteractive,
		Scopes:         []string{"openid"},
		SessionID:      "test-session-id",
		NoRefreshToken: true,
	}
	metaBytes, _ := json.Marshal(metadata)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)

	wantExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
	cacheKey := buildCacheKey(auth.FlowInteractive, fingerprintHash(DefaultADCClientID), "")
	entryBytes, _ := json.Marshal(tokenCacheEntry{
		AccessToken: "cached-session-token",
		TokenType:   "Bearer",
		ExpiresAt:   wantExpiry,
		Scope:       "openid",
		CachedAt:    time.Now(),
		Flow:        auth.FlowInteractive,
		SessionID:   "test-session-id",
	})
	fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(entryBytes)

	status, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.True(t, status.Authenticated)
	assert.Equal(t, "user@example.com", status.Claims.Email)
	assert.Equal(t, auth.IdentityTypeUser, status.IdentityType)
	assert.True(t, status.ExpiresAt.Equal(wantExpiry))
}

func TestGetStatus_UnknownHandler(t *testing.T) {
	p := &Plugin{}
	_, err := p.GetStatus(context.Background(), "unknown", sdkplugin.StatusRequest{})
	assert.Error(t, err)
}

func TestGetToken_UnknownHandler(t *testing.T) {
	p := &Plugin{}
	_, err := p.GetToken(context.Background(), "unknown", sdkplugin.TokenRequest{Scope: "openid"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown handler")
}

func TestGetToken_NoScope(t *testing.T) {
	p, _, _ := newTestPlugin(t)
	_, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scope is required")
}

func TestGetToken_NotAuthenticated(t *testing.T) {
	p, _, _ := newTestPlugin(t)
	_, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
		Scope: "https://www.googleapis.com/auth/cloud-platform",
	})
	assert.Error(t, err)
}

func TestGetToken_CachedToken(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	// Set up stored metadata with refresh token flow
	metadata := &TokenMetadata{
		Claims: &auth.Claims{
			Issuer: "https://accounts.google.com",
			Email:  "user@example.com",
		},
		Flow:      auth.FlowInteractive,
		SessionID: "test-session",
	}
	metaBytes, _ := json.Marshal(metadata)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)
	fake.secrets[SecretKeyRefreshToken] = "test-refresh-token"

	// Pre-populate cache (empty scope in key: refresh always returns full-scope token)
	scope := "https://www.googleapis.com/auth/cloud-platform"
	cacheKey := buildCacheKey(auth.FlowInteractive, fingerprintHash(DefaultADCClientID), "")
	entry := tokenCacheEntry{
		AccessToken: "cached-access-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       scope,
		CachedAt:    time.Now(),
		Flow:        auth.FlowInteractive,
	}
	entryBytes, _ := json.Marshal(entry)
	fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(entryBytes)

	resp, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
		Scope: scope,
	})
	require.NoError(t, err)
	assert.Equal(t, "cached-access-token", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
}

func TestListCachedTokens(t *testing.T) {
	t.Run("no tokens", func(t *testing.T) {
		p, _, _ := newTestPlugin(t)
		tokens, err := p.ListCachedTokens(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("with tokens", func(t *testing.T) {
		p, fake, _ := newTestPlugin(t)

		// Add a refresh token
		metadata := &TokenMetadata{
			Claims:                &auth.Claims{Issuer: "https://accounts.google.com"},
			Flow:                  auth.FlowInteractive,
			SessionID:             "s1",
			RefreshTokenExpiresAt: time.Now().Add(180 * 24 * time.Hour),
		}
		metaBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metaBytes)
		fake.secrets[SecretKeyRefreshToken] = "rt"

		// Add a cached access token
		entry := tokenCacheEntry{
			AccessToken: "at",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			CachedAt:    time.Now(),
			Flow:        auth.FlowInteractive,
		}
		entryBytes, _ := json.Marshal(entry)
		fake.secrets[SecretKeyTokenPrefix+"testkey"] = string(entryBytes)

		tokens, err := p.ListCachedTokens(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.Len(t, tokens, 2)
	})

	t.Run("unknown handler", func(t *testing.T) {
		p := &Plugin{}
		_, err := p.ListCachedTokens(context.Background(), "unknown")
		assert.Error(t, err)
	})
}

func TestPurgeExpiredTokens(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	// Add an expired token
	entry := tokenCacheEntry{
		AccessToken: "expired",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
		CachedAt:    time.Now().Add(-2 * time.Hour),
	}
	entryBytes, _ := json.Marshal(entry)
	fake.secrets[SecretKeyTokenPrefix+"expired"] = string(entryBytes)

	// Add a valid token
	validEntry := tokenCacheEntry{
		AccessToken: "valid",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		CachedAt:    time.Now(),
	}
	validBytes, _ := json.Marshal(validEntry)
	fake.secrets[SecretKeyTokenPrefix+"valid"] = string(validBytes)

	count, err := p.PurgeExpiredTokens(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Valid token should still exist
	_, exists := fake.secrets[SecretKeyTokenPrefix+"valid"]
	assert.True(t, exists)
}

func TestDetectAvailableFlows(t *testing.T) {
	t.Run("no ambient credentials advertises interactive then device code", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
		t.Setenv("CLOUDSDK_CONFIG", t.TempDir())
		t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")

		p, _, _ := newTestPlugin(t)
		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)
		require.Len(t, flows, 2)
		assert.Equal(t, auth.FlowInteractive, flows[0].Flow)
		assert.True(t, flows[0].Available)
		assert.Equal(t, auth.FlowDeviceCode, flows[1].Flow)
		assert.True(t, flows[1].Available)
	})

	t.Run("valid gcloud ADC ranks behind interactive while explicit login and ambient fallback work", func(t *testing.T) {
		adcDir := t.TempDir()
		t.Setenv("CLOUDSDK_CONFIG", adcDir)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
		t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")

		adcCreds := GcloudADCCredentials{
			ClientID:     "gcloud-client-id",
			ClientSecret: "gcloud-client-secret",
			RefreshToken: "gcloud-refresh-token",
			Type:         "authorized_user",
		}
		adcBytes, err := json.Marshal(adcCreds)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(adcDir, "application_default_credentials.json"), adcBytes, 0o600))

		p, _, mockHTTP := newTestPlugin(t)
		// 1) DetectAvailableFlows probe
		mockHTTP.AddResponse(200, TokenResponse{
			AccessToken: "gcloud-probe-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		// 2) Logged-out GetStatus ambient fallback probe
		mockHTTP.AddResponse(200, TokenResponse{
			AccessToken: "gcloud-status-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		// 3) Logged-out GetToken ambient fallback (populates cache)
		mockHTTP.AddResponse(200, TokenResponse{
			AccessToken: "gcloud-fallback-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		// 4) Explicit Login with FlowGcloudADC (refresh + userinfo)
		mockHTTP.AddResponse(200, TokenResponse{
			AccessToken: "gcloud-login-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		mockHTTP.AddResponse(200, map[string]string{
			"sub":   "user-123",
			"email": "user@example.com",
		})

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)
		require.Len(t, flows, 3)
		assert.Equal(t, auth.FlowInteractive, flows[0].Flow, "interactive must rank ahead of ambient gcloud_adc")
		assert.True(t, flows[0].Available)
		assert.Equal(t, auth.FlowGcloudADC, flows[1].Flow)
		assert.True(t, flows[1].Available)
		assert.Equal(t, auth.FlowDeviceCode, flows[2].Flow)
		assert.True(t, flows[2].Available)

		// Ambient GetStatus and GetToken fallback remain functional when logged out
		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, st.Authenticated)
		assert.Equal(t, auth.FlowGcloudADC, st.Flow)

		tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope: "https://www.googleapis.com/auth/cloud-platform",
		})
		require.NoError(t, err)
		assert.Equal(t, "gcloud-fallback-token", tok.AccessToken)
		assert.Equal(t, auth.FlowGcloudADC, tok.Flow)

		// Explicit --flow gcloud-adc login continues to work
		loginResp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowGcloudADC,
		}, nil)
		require.NoError(t, err)
		require.NotNil(t, loginResp.Claims)
		assert.Equal(t, "user@example.com", loginResp.Claims.Email)
	})

	t.Run("impersonation configured does not add a flow", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
		t.Setenv("CLOUDSDK_CONFIG", t.TempDir())
		t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")

		p, _, _ := newTestPlugin(t)
		p.config.ImpersonateServiceAccount = "sa@project.iam.gserviceaccount.com"

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)
		require.Len(t, flows, 2)
		for _, f := range flows {
			assert.NotEqual(t, auth.Flow("impersonation"), f.Flow, "impersonation should not appear as a standalone flow")
		}
	})

	t.Run("unknown handler", func(t *testing.T) {
		p := &Plugin{}
		_, err := p.DetectAvailableFlows(context.Background(), "unknown")
		assert.Error(t, err)
	})

	t.Run("gcloud ADC exists but invalid skips flow", func(t *testing.T) {
		p, _, mockHTTP := newTestPlugin(t)

		// Create a temp ADC file with credentials that will fail validation.
		adcDir := t.TempDir()
		t.Setenv("CLOUDSDK_CONFIG", adcDir)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
		t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")

		adcCreds := GcloudADCCredentials{
			ClientID:     "gcloud-client-id",
			ClientSecret: "gcloud-client-secret",
			RefreshToken: "gcloud-refresh-token",
			Type:         "authorized_user",
		}
		adcBytes, err := json.Marshal(adcCreds)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(adcDir, "application_default_credentials.json"), adcBytes, 0o600))

		// Token endpoint returns RAPT error -> credentials are invalid.
		mockHTTP.AddResponse(400, TokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "reauth related error (invalid_rapt)",
		})

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)
		require.Len(t, flows, 2)
		assert.Equal(t, auth.FlowInteractive, flows[0].Flow)
		assert.Equal(t, auth.FlowDeviceCode, flows[1].Flow)
		for _, f := range flows {
			assert.NotEqual(t, auth.FlowGcloudADC, f.Flow,
				"gcloud-adc flow should not be reported when credentials are invalid")
		}
	})
}

func TestStopAuthHandler(t *testing.T) {
	p := &Plugin{}
	err := p.StopAuthHandler(context.Background(), HandlerName)
	require.NoError(t, err)
}

func TestBinaryName(t *testing.T) {
	t.Run("from config", func(t *testing.T) {
		p := &Plugin{cfg: sdkplugin.ProviderConfig{BinaryName: "mycli"}}
		assert.Equal(t, "mycli", p.binaryName())
	})

	t.Run("default", func(t *testing.T) {
		p := &Plugin{}
		assert.Equal(t, "scafctl", p.binaryName())
	})
}

func TestDeviceCodeLogin(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	// Mock device code response
	mockHTTP.AddResponse(200, DeviceCodeResponse{
		DeviceCode:      "test-device-code",
		UserCode:        "ABCD-1234",
		VerificationURL: "https://accounts.google.com/device",
		ExpiresIn:       300,
		Interval:        5,
	})

	// Mock token response (success on first poll)
	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       "openid email",
	})

	var gotPrompt sdkplugin.DeviceCodePrompt
	cb := func(p sdkplugin.DeviceCodePrompt) {
		gotPrompt = p
	}

	resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
		Flow:   auth.FlowDeviceCode,
		Scopes: []string{"openid", "email"},
	}, cb)
	require.NoError(t, err)
	assert.NotNil(t, resp.Claims)
	assert.False(t, resp.ExpiresAt.IsZero())
	assert.Equal(t, "ABCD-1234", gotPrompt.UserCode)
	assert.Equal(t, "https://accounts.google.com/device", gotPrompt.VerificationURI)
}

func TestDeviceCodeLogin_Timeout(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	var sleepCalls int
	p.clock = clock.Mock{
		SleepFunc: func(ctx context.Context, _ time.Duration) error {
			sleepCalls++
			if sleepCalls == 1 {
				return nil
			}
			<-ctx.Done()
			return ctx.Err()
		},
	}

	// Mock device code response
	mockHTTP.AddResponse(200, DeviceCodeResponse{
		DeviceCode:      "test-device-code",
		UserCode:        "ABCD-1234",
		VerificationURL: "https://accounts.google.com/device",
		ExpiresIn:       1,
		Interval:        5,
	})
	mockHTTP.AddResponse(200, map[string]string{
		"error": "authorization_pending",
	})

	_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
		Flow:    auth.FlowDeviceCode,
		Timeout: 20 * time.Millisecond,
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTimeout)
}

type timeoutNetErr struct{}

func (timeoutNetErr) Error() string   { return "request timeout" }
func (timeoutNetErr) Timeout() bool   { return true }
func (timeoutNetErr) Temporary() bool { return true }

func TestPollGCPDeviceToken_PostResponseTimingAndErrors(t *testing.T) {
	t.Run("waits interval plus 1s safety margin after each response and honors slow_down server interval", func(t *testing.T) {
		p, _, mockHTTP := newTestPlugin(t)

		var sleeps []time.Duration
		p.clock = clock.Mock{
			SleepFunc: func(_ context.Context, d time.Duration) error {
				sleeps = append(sleeps, d)
				return nil
			},
		}

		// Poll 1: authorization_pending -> keeps base 5s (sleep 6s)
		mockHTTP.AddResponse(400, map[string]any{
			"error": "authorization_pending",
		})
		// Poll 2: transient non-timeout network error -> keeps base 5s (sleep 6s)
		mockHTTP.AddError(errors.New("temporary connection reset"))
		// Poll 3: slow_down without server interval -> 5s + 5s = 10s (sleep 11s)
		mockHTTP.AddResponse(400, map[string]any{
			"error": "slow_down",
		})
		// Poll 4: slow_down with larger server interval (20s > 10s + 5s) -> 20s (sleep 21s)
		mockHTTP.AddResponse(400, map[string]any{
			"error":    "slow_down",
			"interval": 20,
		})
		// Poll 5: timeout network error -> doubles 20s to 40s (sleep 41s)
		mockHTTP.AddError(timeoutNetErr{})
		// Poll 6: success
		mockHTTP.AddResponse(200, TokenResponse{
			AccessToken:  "device-access-token",
			RefreshToken: "device-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        "openid email",
		})

		resp, err := p.pollGCPDeviceToken(context.Background(), &DeviceCodeResponse{
			DeviceCode: "dc-1",
			Interval:   2, // clamped up to 5s minimum
		}, "custom-client", "custom-secret")
		require.NoError(t, err)
		assert.Equal(t, "device-access-token", resp.AccessToken)
		assert.Equal(t, "device-refresh-token", resp.RefreshToken)
		assert.Equal(t, []time.Duration{
			6 * time.Second,
			6 * time.Second,
			6 * time.Second,
			11 * time.Second,
			21 * time.Second,
			41 * time.Second,
		}, sleeps)
	})

	t.Run("context cancelled maps to ErrUserCancelled", func(t *testing.T) {
		p, _, _ := newTestPlugin(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := p.pollGCPDeviceToken(ctx, &DeviceCodeResponse{DeviceCode: "dc", Interval: 5}, "cid", "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUserCancelled)
		assert.Contains(t, err.Error(), "authentication cancelled")
	})

	t.Run("terminal OAuth error preserves sanitized message", func(t *testing.T) {
		p, _, mockHTTP := newTestPlugin(t)
		mockHTTP.AddResponse(400, TokenErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "bad client secret",
		})

		_, err := p.pollGCPDeviceToken(context.Background(), &DeviceCodeResponse{DeviceCode: "dc", Interval: 5}, "cid", "bad")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token request failed: invalid_client - bad client secret")
	})

	t.Run("malformed JSON token response fails without retrying", func(t *testing.T) {
		p, _, mockHTTP := newTestPlugin(t)
		// Empty nil body decodes as EOF JSON parse failure.
		mockHTTP.AddResponse(200, nil)

		_, err := p.pollGCPDeviceToken(context.Background(), &DeviceCodeResponse{DeviceCode: "dc", Interval: 5}, "cid", "secret")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse token response")
		assert.Len(t, mockHTTP.GetRequests(), 1)
	})
}

func TestSecretPrefixRegexAndHostValidation(t *testing.T) {
	t.Run("fakeHostService enforces host secret-name and regex rules", func(t *testing.T) {
		fake := newFakeHostService()
		hc := newFakeHostClient(fake)
		ctx := context.Background()

		invalidNames := []string{
			"",
			"..",
			"scafctl..bad",
			"bad:colon",
			"bad/slash",
			".leading-dot",
			"-leading-dash",
			strings.Repeat("a", 256),
		}
		for _, name := range invalidNames {
			err := hc.SetSecret(ctx, name, "v")
			assert.Errorf(t, err, "SetSecret must reject %q", name)

			_, _, err = hc.GetSecret(ctx, name)
			assert.Errorf(t, err, "GetSecret must reject %q", name)

			err = hc.DeleteSecret(ctx, name)
			assert.Errorf(t, err, "DeleteSecret must reject %q", name)
		}

		require.NoError(t, hc.SetSecret(ctx, "scafctl.auth.gcp.token.k1", "v1"))
		require.NoError(t, hc.SetSecret(ctx, "other.scafctl.auth.gcp.token.k2", "v2"))

		// Unanchored regex matches both; anchored regex matches only literal prefix.
		unanchored, err := hc.ListSecrets(ctx, "scafctl\\.auth\\.gcp\\.token\\.")
		require.NoError(t, err)
		assert.Len(t, unanchored, 2)

		prefixed, err := hc.ListSecretsByPrefix(ctx, SecretKeyTokenPrefix)
		require.NoError(t, err)
		assert.Equal(t, []string{"scafctl.auth.gcp.token.k1"}, prefixed)

		// Invalid regex and overlong pattern are rejected.
		_, err = hc.ListSecrets(ctx, "[unterminated")
		assert.Error(t, err)

		_, err = hc.ListSecrets(ctx, strings.Repeat("a", sdkplugin.MaxHostSecretPatternLength+1))
		assert.Error(t, err)
	})

	t.Run("token cache operations isolate literal prefix against plugintest.FakeHostService", func(t *testing.T) {
		hc, hostFake := plugintest.NewFakeHostClient(t)
		ctx := sdkplugin.WithHostClient(context.Background(), hc)

		validJSON, err := json.Marshal(tokenCacheEntry{
			AccessToken: "valid-at",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
			CachedAt:    time.Now(),
			Flow:        auth.FlowInteractive,
		})
		require.NoError(t, err)
		expiredJSON, err := json.Marshal(tokenCacheEntry{
			AccessToken: "expired-at",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(-time.Hour),
			CachedAt:    time.Now().Add(-2 * time.Hour),
			Flow:        auth.FlowInteractive,
		})
		require.NoError(t, err)

		// Populate real prefix keys alongside decoys that match unanchored or unescaped dot patterns.
		decoys := map[string]string{
			"other." + SecretKeyTokenPrefix + "decoy":   string(expiredJSON),
			"scafctlXauthYgcpZtokenWdecoy":              string(expiredJSON),
			"scafctl.auth.gcp.tokenXdecoy":              string(expiredJSON),
			SecretKeyRefreshToken:                       "active-refresh-token",
			"other.scafctl.auth.gcp.refresh_token.rev1": "other-rev",
			"scafctl_auth_gcp_refresh_token_decoy":      "underscore-decoy",
		}
		for k, v := range decoys {
			require.NoError(t, hostFake.PutSecret(k, v))
		}
		require.NoError(t, hostFake.PutSecret(SecretKeyTokenPrefix+"valid", string(validJSON)))
		require.NoError(t, hostFake.PutSecret(SecretKeyTokenPrefix+"expired", string(expiredJSON)))

		entries, err := cacheListEntries(ctx, hc)
		require.NoError(t, err)
		assert.Len(t, entries, 2, "cacheListEntries must ignore decoy keys")

		purged, err := cachePurgeExpired(ctx, hc)
		require.NoError(t, err)
		assert.Equal(t, 1, purged, "cachePurgeExpired must purge only expired key under literal prefix")

		cacheClearExceptWithPrefix(ctx, logr.Discard(), hc, SecretKeyTokenPrefix, SecretKeyTokenPrefix+"valid")
		_, validStillExists := hostFake.Secret(SecretKeyTokenPrefix + "valid")
		assert.True(t, validStillExists)

		cacheClear(ctx, logr.Discard(), hc)
		_, validAfterClear := hostFake.Secret(SecretKeyTokenPrefix + "valid")
		assert.False(t, validAfterClear)

		for k, want := range decoys {
			got, ok := hostFake.Secret(k)
			assert.Truef(t, ok, "decoy secret %q must remain untouched", k)
			assert.Equalf(t, want, got, "decoy secret %q value must remain unchanged", k)
		}
	})

	t.Run("ListSecretsByPrefix ignores out-of-prefix keys returned by host", func(t *testing.T) {
		fake := newFakeHostService()
		hc := newFakeHostClient(fake)
		ctx := context.Background()

		expiredJSON, _ := json.Marshal(tokenCacheEntry{
			AccessToken: "exp",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(-time.Hour),
			CachedAt:    time.Now().Add(-2 * time.Hour),
		})
		fake.secrets["unrelated.secret"] = string(expiredJSON)
		fake.secrets[SecretKeyTokenPrefix+"k1"] = string(expiredJSON)
		fake.listSecretsFunc = func(_ context.Context, _ string) ([]string, bool, error) {
			return []string{"unrelated.secret", SecretKeyTokenPrefix + "k1"}, true, nil
		}

		entries, err := cacheListEntriesWithPrefix(ctx, hc, SecretKeyTokenPrefix)
		require.NoError(t, err)
		require.Len(t, entries, 1)

		purged, err := cachePurgeExpiredWithPrefix(ctx, hc, SecretKeyTokenPrefix)
		require.NoError(t, err)
		assert.Equal(t, 1, purged)
		assert.NotEmpty(t, fake.secrets["unrelated.secret"])

		fake.secrets[SecretKeyTokenPrefix+"k2"] = string(expiredJSON)
		fake.listSecretsFunc = func(_ context.Context, _ string) ([]string, bool, error) {
			return []string{"unrelated.secret", SecretKeyTokenPrefix + "k2"}, true, nil
		}
		cacheClearExceptWithPrefix(ctx, logr.Discard(), hc, SecretKeyTokenPrefix, "")
		assert.NotEmpty(t, fake.secrets["unrelated.secret"])
		assert.Empty(t, fake.secrets[SecretKeyTokenPrefix+"k2"])
	})
}

func TestServiceAccountStatus(t *testing.T) {
	p, _, _ := newTestPlugin(t)
	// Without GOOGLE_APPLICATION_CREDENTIALS set, this should return not authenticated
	status, err := p.serviceAccountStatus(context.Background())
	require.NoError(t, err)
	assert.False(t, status.Authenticated)
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "valid empty config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "valid impersonation config",
			config: &Config{
				ImpersonateServiceAccount: "sa@project.iam.gserviceaccount.com",
			},
			wantErr: false,
		},
		{
			name: "invalid short impersonation",
			config: &Config{
				ImpersonateServiceAccount: "ab",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtractClaims(t *testing.T) {
	t.Run("no id token", func(t *testing.T) {
		claims, err := extractClaims(&TokenResponse{})
		require.NoError(t, err)
		assert.Equal(t, "https://accounts.google.com", claims.Issuer)
	})

	t.Run("invalid id token format", func(t *testing.T) {
		_, err := extractClaimsFromIDToken("invalid")
		assert.Error(t, err)
	})

	t.Run("invalid base64 payload", func(t *testing.T) {
		_, err := extractClaimsFromIDToken("header.!!!invalid!!!.signature")
		assert.Error(t, err)
	})
}

func TestTokenCache(t *testing.T) {
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)
	ctx := context.Background()

	token := &auth.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "openid",
		Flow:        auth.FlowInteractive,
	}

	// Set
	err := cacheSet(ctx, hostClient, "testkey", token)
	require.NoError(t, err)

	// Get
	cached, err := cacheGet(ctx, hostClient, "testkey")
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, "test-token", cached.AccessToken)
	assert.Equal(t, "Bearer", cached.TokenType)

	// Get non-existent
	missing, err := cacheGet(ctx, hostClient, "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, missing)
}

func TestBuildCacheKey(t *testing.T) {
	key1 := buildCacheKey("flow1", "fp1", "scope1")
	key2 := buildCacheKey("flow1", "fp1", "scope1")
	key3 := buildCacheKey("flow2", "fp1", "scope1")

	assert.Equal(t, key1, key2, "same inputs should produce same key")
	assert.NotEqual(t, key1, key3, "different inputs should produce different key")

	// Scope ordering should not affect the key.
	keyAB := buildCacheKey("flow1", "fp1", "scopeA scopeB")
	keyBA := buildCacheKey("flow1", "fp1", "scopeB scopeA")
	assert.Equal(t, keyAB, keyBA, "same scopes in different order should produce same key")

	// Google short aliases should be canonicalized to long form.
	keyShort := buildCacheKey("flow1", "fp1", "openid email profile")
	keyLong := buildCacheKey("flow1", "fp1", "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile")
	assert.Equal(t, keyShort, keyLong, "scope aliases should produce same key as canonical form")
}

func TestFingerprintHash(t *testing.T) {
	h1 := fingerprintHash("test")
	h2 := fingerprintHash("test")
	h3 := fingerprintHash("other")

	assert.Equal(t, h1, h2)
	assert.NotEqual(t, h1, h3)
	assert.Len(t, h1, 16) // 8 bytes hex-encoded
}

func TestLogoutClearsSecrets(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	// Populate secrets
	fake.secrets[SecretKeyRefreshToken] = "rt"
	fake.secrets[SecretKeyMetadata] = `{"flow": "interactive"}`
	fake.secrets[SecretKeyTokenPrefix+"key1"] = `{"accessToken": "at"}`

	err := p.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{})
	require.NoError(t, err)

	assert.Empty(t, fake.secrets, "all secrets should be cleared after logout")
}

// BenchmarkGetToken_Cached benchmarks the cached token path.
func BenchmarkGetToken_Cached(b *testing.B) {
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)
	mockHTTP := NewMockHTTPClient()

	p := &Plugin{
		config:           DefaultConfig(),
		httpClient:       mockHTTP,
		clock:            clock.Mock{},
		cachedHostClient: hostClient,
		cfg:              sdkplugin.ProviderConfig{BinaryName: "bench"},
	}

	// Set up stored metadata with refresh token flow
	metadata := &TokenMetadata{
		Claims: &auth.Claims{Issuer: "https://accounts.google.com"},
		Flow:   auth.FlowInteractive,
	}
	metaBytes, _ := json.Marshal(metadata)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)
	fake.secrets[SecretKeyRefreshToken] = "refresh"

	scope := "https://www.googleapis.com/auth/cloud-platform"
	// Use empty scope in key: refresh always returns a full-scope token (matches getStoredRefreshToken keying).
	cacheKey := buildCacheKey(auth.FlowInteractive, fingerprintHash(DefaultADCClientID), "")
	entry := tokenCacheEntry{
		AccessToken: "cached",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       scope,
		CachedAt:    time.Now(),
		Flow:        auth.FlowInteractive,
	}
	entryBytes, _ := json.Marshal(entry)
	fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(entryBytes)

	ctx := context.Background()

	b.ResetTimer()
	for range b.N {
		_, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetStatus_NoNetwork benchmarks the status check path without network.
func BenchmarkGetStatus_NoNetwork(b *testing.B) {
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)

	p := &Plugin{
		config:           DefaultConfig(),
		httpClient:       NewMockHTTPClient(),
		clock:            clock.Mock{},
		cachedHostClient: hostClient,
		cfg:              sdkplugin.ProviderConfig{BinaryName: "bench"},
	}

	ctx := context.Background()

	b.ResetTimer()
	for range b.N {
		_, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		if err != nil {
			b.Fatal(err)
		}
	}
}
