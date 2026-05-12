package gcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
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
	assert.Len(t, handlers[0].Capabilities, 4)
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
		err := p.Logout(context.Background(), HandlerName)
		require.NoError(t, err)
	})

	t.Run("unknown handler", func(t *testing.T) {
		p := &Plugin{}
		err := p.Logout(context.Background(), "unknown")
		assert.Error(t, err)
	})
}

func TestGetStatus_NotAuthenticated(t *testing.T) {
	p, _, _ := newTestPlugin(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
	t.Setenv("CLOUDSDK_CONFIG", t.TempDir())
	t.Setenv("GCE_METADATA_HOST", "192.0.2.1")
	status, err := p.GetStatus(context.Background(), HandlerName)
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
		Flow:      auth.FlowInteractive,
		Scopes:    []string{"openid"},
		SessionID: "test-session-id",
	}
	metaBytes, _ := json.Marshal(metadata)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)

	status, err := p.GetStatus(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.True(t, status.Authenticated)
	assert.Equal(t, "user@example.com", status.Claims.Email)
	assert.Equal(t, auth.IdentityTypeUser, status.IdentityType)
}

func TestGetStatus_UnknownHandler(t *testing.T) {
	p := &Plugin{}
	_, err := p.GetStatus(context.Background(), "unknown")
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

	// Pre-populate cache
	scope := "https://www.googleapis.com/auth/cloud-platform"
	cacheKey := buildCacheKey(auth.FlowInteractive, fingerprintHash(DefaultADCClientID), scope)
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
	t.Run("no credentials", func(t *testing.T) {
		// Clear environment variables that DetectAvailableFlows checks
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
		t.Setenv("CLOUDSDK_CONFIG", t.TempDir()) // point to empty dir
		t.Setenv("GCE_METADATA_HOST", "192.0.2.1")

		p, _, _ := newTestPlugin(t)
		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.Empty(t, flows)
	})

	t.Run("impersonation configured does not add a flow", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
		t.Setenv("CLOUDSDK_CONFIG", t.TempDir())
		t.Setenv("GCE_METADATA_HOST", "192.0.2.1")

		p, _, _ := newTestPlugin(t)
		p.config.ImpersonateServiceAccount = "sa@project.iam.gserviceaccount.com"

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)

		for _, f := range flows {
			assert.NotEqual(t, auth.Flow("impersonation"), f.Flow, "impersonation should not appear as a standalone flow")
		}
	})

	t.Run("unknown handler", func(t *testing.T) {
		p := &Plugin{}
		_, err := p.DetectAvailableFlows(context.Background(), "unknown")
		assert.Error(t, err)
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

	// Mock device code response
	mockHTTP.AddResponse(200, DeviceCodeResponse{
		DeviceCode:      "test-device-code",
		UserCode:        "ABCD-1234",
		VerificationURL: "https://accounts.google.com/device",
		ExpiresIn:       1,
		Interval:        5,
	})

	// Mock pending responses
	for range 100 {
		mockHTTP.AddResponse(200, map[string]string{
			"error": "authorization_pending",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{
		Flow:    auth.FlowDeviceCode,
		Timeout: 100 * time.Millisecond,
	}, nil)
	assert.Error(t, err)
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

	err := p.Logout(context.Background(), HandlerName)
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
	cacheKey := buildCacheKey(auth.FlowInteractive, fingerprintHash(DefaultADCClientID), scope)
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
		_, err := p.GetStatus(ctx, HandlerName)
		if err != nil {
			b.Fatal(err)
		}
	}
}
