// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreCredentials(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	tokenResp := &TokenResponse{
		AccessToken:  "at",
		RefreshToken: "rt",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "openid",
	}

	err := p.storeCredentials(context.Background(), tokenResp, auth.FlowInteractive, []string{"openid"}, "", "test-client-id")
	require.NoError(t, err)

	// Verify refresh token stored
	assert.Equal(t, "rt", fake.secrets[SecretKeyRefreshToken])

	// Verify metadata stored
	var meta TokenMetadata
	require.NoError(t, json.Unmarshal([]byte(fake.secrets[SecretKeyMetadata]), &meta))
	assert.Equal(t, auth.FlowInteractive, meta.Flow)
	assert.NotEmpty(t, meta.SessionID)
	assert.False(t, meta.RefreshTokenExpiresAt.IsZero())
}

func TestStoreCredentials_NoRefreshToken(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	tokenResp := &TokenResponse{
		AccessToken: "at",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	err := p.storeCredentials(context.Background(), tokenResp, auth.FlowServicePrincipal, nil, "existing-session", "")
	require.NoError(t, err)

	// No refresh token should be stored
	_, exists := fake.secrets[SecretKeyRefreshToken]
	assert.False(t, exists)

	var meta TokenMetadata
	require.NoError(t, json.Unmarshal([]byte(fake.secrets[SecretKeyMetadata]), &meta))
	assert.Equal(t, "existing-session", meta.SessionID)
	assert.True(t, meta.RefreshTokenExpiresAt.IsZero())
}

func TestStoreCredentials_NoHostClient(t *testing.T) {
	p := &Plugin{config: DefaultConfig()}
	err := p.storeCredentials(context.Background(), &TokenResponse{}, auth.FlowInteractive, nil, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "host service not available")
}

func TestStoreMetadataOnly(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	claims := &auth.Claims{
		Issuer: "https://accounts.google.com",
		Email:  "sa@project.iam.gserviceaccount.com",
	}

	err := p.storeMetadataOnly(context.Background(), claims, auth.FlowServicePrincipal, []string{"cloud-platform"})
	require.NoError(t, err)

	var meta TokenMetadata
	require.NoError(t, json.Unmarshal([]byte(fake.secrets[SecretKeyMetadata]), &meta))
	assert.Equal(t, auth.FlowServicePrincipal, meta.Flow)
	assert.Equal(t, "sa@project.iam.gserviceaccount.com", meta.Claims.Email)
	assert.NotEmpty(t, meta.SessionID)
}

func TestStoreMetadataOnly_NoHostClient(t *testing.T) {
	p := &Plugin{config: DefaultConfig()}
	err := p.storeMetadataOnly(context.Background(), &auth.Claims{}, auth.FlowMetadata, nil)
	assert.Error(t, err)
}

func TestLoadRefreshToken(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	t.Run("found", func(t *testing.T) {
		fake.secrets[SecretKeyRefreshToken] = "my-refresh-token"
		token, err := p.loadRefreshToken(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "my-refresh-token", token)
	})

	t.Run("not found", func(t *testing.T) {
		delete(fake.secrets, SecretKeyRefreshToken)
		_, err := p.loadRefreshToken(context.Background())
		assert.Error(t, err)
	})
}

func TestLoadMetadata(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	t.Run("valid", func(t *testing.T) {
		meta := TokenMetadata{
			Claims: &auth.Claims{Email: "user@example.com"},
			Flow:   auth.FlowInteractive,
		}
		data, _ := json.Marshal(meta)
		fake.secrets[SecretKeyMetadata] = string(data)

		loaded, err := p.loadMetadata(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", loaded.Claims.Email)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		fake.secrets[SecretKeyMetadata] = "not-json"
		_, err := p.loadMetadata(context.Background())
		assert.Error(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		delete(fake.secrets, SecretKeyMetadata)
		_, err := p.loadMetadata(context.Background())
		assert.Error(t, err)
	})
}

func TestGetSecret(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	t.Run("found", func(t *testing.T) {
		fake.secrets["key1"] = "value1"
		v, err := p.getSecret(context.Background(), "key1")
		require.NoError(t, err)
		assert.Equal(t, "value1", v)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := p.getSecret(context.Background(), "nonexistent")
		assert.Error(t, err)
	})

	t.Run("no host client", func(t *testing.T) {
		p2 := &Plugin{config: DefaultConfig()}
		_, err := p2.getSecret(context.Background(), "key")
		assert.Error(t, err)
	})
}

func TestSecretExists(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	fake.secrets["exists"] = "value"
	assert.True(t, p.secretExists(context.Background(), "exists"))
	assert.False(t, p.secretExists(context.Background(), "missing"))
}

func TestExtractClaimsFromIDToken_Valid(t *testing.T) {
	// Build a valid JWT payload
	payload := map[string]any{
		"iss":   "https://accounts.google.com",
		"sub":   "1234567890",
		"email": "user@example.com",
		"name":  "Test User",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	payloadBytes, _ := json.Marshal(payload)

	idToken := base64.RawURLEncoding.EncodeToString([]byte("header")) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("signature"))

	claims, err := extractClaimsFromIDToken(idToken)
	require.NoError(t, err)
	assert.Equal(t, "https://accounts.google.com", claims.Issuer)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.Equal(t, "Test User", claims.Name)
	assert.Equal(t, "user", claims.Username)
}

func TestExtractClaims_WithIDToken(t *testing.T) {
	payload := map[string]any{
		"iss":   "https://accounts.google.com",
		"email": "user@example.com",
	}
	payloadBytes, _ := json.Marshal(payload)
	idToken := "h." + base64.RawURLEncoding.EncodeToString(payloadBytes) + ".s"

	tokenResp := &TokenResponse{IDToken: idToken}
	claims, err := extractClaims(tokenResp)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Email)
}

func TestCacheClear(t *testing.T) {
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)
	ctx := context.Background()

	fake.secrets[SecretKeyTokenPrefix+"key1"] = `{"accessToken":"at1"}`
	fake.secrets[SecretKeyTokenPrefix+"key2"] = `{"accessToken":"at2"}`
	fake.secrets["other-key"] = "should-remain"

	lgr := logr.FromContextOrDiscard(ctx)
	cacheClear(ctx, lgr, hostClient)

	assert.Empty(t, fake.secrets[SecretKeyTokenPrefix+"key1"])
	assert.Equal(t, "should-remain", fake.secrets["other-key"])
}

func TestCacheListEntries(t *testing.T) {
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)
	ctx := context.Background()

	entry := tokenCacheEntry{
		AccessToken: "at",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
		CachedAt:    time.Now(),
		Flow:        auth.FlowInteractive,
		SessionID:   "s1",
	}
	data, _ := json.Marshal(entry)
	fake.secrets[SecretKeyTokenPrefix+"key1"] = string(data)

	entries, err := cacheListEntries(ctx, hostClient)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, HandlerName, entries[0].Handler)
	assert.Equal(t, "access", entries[0].TokenKind)
	assert.Equal(t, "Bearer", entries[0].TokenType)
	assert.Equal(t, "s1", entries[0].SessionID)
}

func TestCachePurgeExpired_Mixed(t *testing.T) {
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)
	ctx := context.Background()

	expired := tokenCacheEntry{ExpiresAt: time.Now().Add(-time.Hour)}
	valid := tokenCacheEntry{ExpiresAt: time.Now().Add(time.Hour)}

	expiredData, _ := json.Marshal(expired)
	validData, _ := json.Marshal(valid)

	fake.secrets[SecretKeyTokenPrefix+"exp"] = string(expiredData)
	fake.secrets[SecretKeyTokenPrefix+"val"] = string(validData)

	count, err := cachePurgeExpired(ctx, hostClient)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	_, existsValid := fake.secrets[SecretKeyTokenPrefix+"val"]
	assert.True(t, existsValid)
}

func TestGetStatus_WithSACredentials(t *testing.T) {
	p, _, _ := newTestPlugin(t)

	// Clear env to ensure no SA credentials
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
	t.Setenv("CLOUDSDK_CONFIG", t.TempDir())
	t.Setenv("GCE_METADATA_HOST", "192.0.2.1")

	status, err := p.GetStatus(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.False(t, status.Authenticated)
}

func TestGetStatus_WithMetadataFlow(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	metadata := &TokenMetadata{
		Claims: &auth.Claims{
			Issuer:  "https://accounts.google.com",
			Subject: "sa@project.iam.gserviceaccount.com",
			Email:   "sa@project.iam.gserviceaccount.com",
		},
		Flow:   auth.FlowMetadata,
		Scopes: []string{"cloud-platform"},
	}
	metaBytes, _ := json.Marshal(metadata)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)

	status, err := p.GetStatus(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.True(t, status.Authenticated)
}

func TestResolveAndAcquireToken_Impersonation(t *testing.T) {
	p, fake, mockHTTP := newTestPlugin(t)
	p.config.ImpersonateServiceAccount = "target@project.iam.gserviceaccount.com"

	// Set up refresh token so acquireSourceToken works
	fake.secrets[SecretKeyRefreshToken] = "refresh-token"
	meta := &TokenMetadata{
		Claims: &auth.Claims{Issuer: "https://accounts.google.com"},
		Flow:   auth.FlowInteractive,
	}
	metaBytes, _ := json.Marshal(meta)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)

	// Mock mint token response (source token)
	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken: "source-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})

	// Mock impersonation response
	mockHTTP.AddResponse(200, ImpersonationResponse{
		AccessToken: "impersonated-token",
		ExpireTime:  time.Now().Add(time.Hour).Format(time.RFC3339),
	})

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
	t.Setenv("CLOUDSDK_CONFIG", t.TempDir())

	token, err := p.resolveAndAcquireToken(context.Background(), "cloud-platform", false)
	require.NoError(t, err)
	assert.Equal(t, "impersonated-token", token.AccessToken)
}

func TestMintToken_Success(t *testing.T) {
	p, fake, mockHTTP := newTestPlugin(t)

	fake.secrets[SecretKeyRefreshToken] = "my-refresh-token"
	meta := &TokenMetadata{
		Claims: &auth.Claims{Issuer: "https://accounts.google.com"},
		Flow:   auth.FlowInteractive,
	}
	metaBytes, _ := json.Marshal(meta)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)

	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken: "new-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       "openid",
	})

	token, err := p.mintToken(context.Background(), "openid")
	require.NoError(t, err)
	assert.Equal(t, "new-access-token", token.AccessToken)
}

func TestMintToken_NoRefreshToken(t *testing.T) {
	p, _, _ := newTestPlugin(t)

	_, err := p.mintToken(context.Background(), "openid")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotAuthenticated)
}

func TestMintToken_InvalidGrant(t *testing.T) {
	p, fake, mockHTTP := newTestPlugin(t)

	fake.secrets[SecretKeyRefreshToken] = "expired-token"
	meta := &TokenMetadata{
		Claims: &auth.Claims{Issuer: "https://accounts.google.com"},
		Flow:   auth.FlowInteractive,
	}
	metaBytes, _ := json.Marshal(meta)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)

	mockHTTP.AddResponse(400, TokenErrorResponse{
		Error:            "invalid_grant",
		ErrorDescription: "Token has been expired or revoked.",
	})

	_, err := p.mintToken(context.Background(), "openid")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestMintToken_RefreshTokenRotation(t *testing.T) {
	p, fake, mockHTTP := newTestPlugin(t)

	fake.secrets[SecretKeyRefreshToken] = "old-refresh-token"
	meta := &TokenMetadata{
		Claims:    &auth.Claims{Issuer: "https://accounts.google.com"},
		Flow:      auth.FlowInteractive,
		SessionID: "session-1",
	}
	metaBytes, _ := json.Marshal(meta)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)

	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken:  "new-at",
		RefreshToken: "new-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	})

	token, err := p.mintToken(context.Background(), "openid")
	require.NoError(t, err)
	assert.Equal(t, "new-at", token.AccessToken)

	// The new refresh token should be stored
	assert.Equal(t, "new-refresh-token", fake.secrets[SecretKeyRefreshToken])
}

func TestGetStoredRefreshToken_Cached(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	fake.secrets[SecretKeyRefreshToken] = "rt"
	meta := &TokenMetadata{
		Claims: &auth.Claims{Issuer: "https://accounts.google.com"},
		Flow:   auth.FlowInteractive,
	}
	metaBytes, _ := json.Marshal(meta)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)

	scope := "openid"
	cacheKey := buildCacheKey(auth.FlowInteractive, fingerprintHash(DefaultADCClientID), scope)
	entry := tokenCacheEntry{
		AccessToken: "cached-at",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
		CachedAt:    time.Now(),
		Flow:        auth.FlowInteractive,
	}
	data, _ := json.Marshal(entry)
	fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(data)

	token, err := p.getStoredRefreshToken(context.Background(), scope, false)
	require.NoError(t, err)
	assert.Equal(t, "cached-at", token.AccessToken)
}

func TestRevokeRefreshToken(t *testing.T) {
	t.Run("with token", func(t *testing.T) {
		p, fake, mockHTTP := newTestPlugin(t)
		fake.secrets[SecretKeyRefreshToken] = "rt"
		mockHTTP.AddResponse(200, map[string]string{})

		err := p.revokeRefreshToken(context.Background())
		require.NoError(t, err)
	})

	t.Run("no token", func(t *testing.T) {
		p, _, _ := newTestPlugin(t)
		err := p.revokeRefreshToken(context.Background())
		require.NoError(t, err) // should not error
	})
}

func TestFetchUserinfoClaims(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	mockHTTP.AddResponse(200, map[string]any{
		"sub":   "1234",
		"email": "user@example.com",
		"name":  "Test User",
	})

	claims, err := p.fetchUserinfoClaims(context.Background(), "access-token")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.Equal(t, "Test User", claims.Name)
}

func TestImpersonateServiceAccount_Success(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	expireTime := time.Now().Add(time.Hour).Format(time.RFC3339)
	mockHTTP.AddResponse(200, ImpersonationResponse{
		AccessToken: "impersonated-at",
		ExpireTime:  expireTime,
	})

	token, err := p.impersonateServiceAccount(
		context.Background(),
		"source-token",
		"target@project.iam.gserviceaccount.com",
		[]string{"cloud-platform"},
	)
	require.NoError(t, err)
	assert.Equal(t, "impersonated-at", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
}

func TestImpersonateServiceAccount_Forbidden(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	mockHTTP.AddResponse(403, map[string]any{
		"error": map[string]any{
			"message": "Permission denied",
		},
	})

	_, err := p.impersonateServiceAccount(
		context.Background(),
		"source-token",
		"target@project.iam.gserviceaccount.com",
		[]string{"cloud-platform"},
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "impersonation denied")
}

func TestImpersonateServiceAccount_Unauthorized(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	mockHTTP.AddResponse(401, map[string]any{
		"error": map[string]any{
			"message": "Token expired",
		},
	})

	_, err := p.impersonateServiceAccount(
		context.Background(),
		"source-token",
		"target@project.iam.gserviceaccount.com",
		[]string{"cloud-platform"},
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "source identity is not authenticated")
}

func TestGetImpersonatedToken_Cached(t *testing.T) {
	p, fake, _ := newTestPlugin(t)
	p.config.ImpersonateServiceAccount = "target@project.iam.gserviceaccount.com"

	scope := "cloud-platform"
	fingerprint := fingerprintHash("target@project.iam.gserviceaccount.com")
	cacheKey := buildCacheKey("impersonation", fingerprint, scope)

	entry := tokenCacheEntry{
		AccessToken: "cached-impersonated",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
		CachedAt:    time.Now(),
	}
	data, _ := json.Marshal(entry)
	fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(data)

	token, err := p.getImpersonatedToken(context.Background(), "source-at", scope, false)
	require.NoError(t, err)
	assert.Equal(t, "cached-impersonated", token.AccessToken)
}

func TestGetImpersonatedToken_Fresh(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)
	p.config.ImpersonateServiceAccount = "target@project.iam.gserviceaccount.com"

	mockHTTP.AddResponse(200, ImpersonationResponse{
		AccessToken: "fresh-impersonated",
		ExpireTime:  time.Now().Add(time.Hour).Format(time.RFC3339),
	})

	token, err := p.getImpersonatedToken(context.Background(), "source-at", "cloud-platform", true)
	require.NoError(t, err)
	assert.Equal(t, "fresh-impersonated", token.AccessToken)
}

func TestFormatGcloudTokenError(t *testing.T) {
	tests := []struct {
		name     string
		errResp  TokenErrorResponse
		contains string
	}{
		{
			name: "invalid_rapt",
			errResp: TokenErrorResponse{
				Error:            "invalid_grant",
				ErrorDescription: "invalid_rapt token",
			},
			contains: "reauthenticate",
		},
		{
			name: "invalid_grant",
			errResp: TokenErrorResponse{
				Error:            "invalid_grant",
				ErrorDescription: "Token has expired",
			},
			contains: "expired or been revoked",
		},
		{
			name: "other error",
			errResp: TokenErrorResponse{
				Error:            "invalid_client",
				ErrorDescription: "bad client",
			},
			contains: "token refresh failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := formatGcloudTokenError(tt.errResp, "testcli")
			assert.Contains(t, err.Error(), tt.contains)
		})
	}
}

func TestGcloudADCLogin_Success(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	// Create a temp ADC file
	adcDir := t.TempDir()
	t.Setenv("CLOUDSDK_CONFIG", adcDir)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	adcCreds := GcloudADCCredentials{
		ClientID:     "gcloud-client-id",
		ClientSecret: "gcloud-client-secret",
		RefreshToken: "gcloud-refresh-token",
		Type:         "authorized_user",
	}
	adcBytes, _ := json.Marshal(adcCreds)
	require.NoError(t, os.WriteFile(adcDir+"/application_default_credentials.json", adcBytes, 0o600))

	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken: "gcloud-at",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       "cloud-platform",
	})

	resp, err := p.gcloudADCLogin(context.Background(), sdkplugin.LoginRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp.Claims)
}

func TestGcloudADCLogin_NoCreds(t *testing.T) {
	p, _, _ := newTestPlugin(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("CLOUDSDK_CONFIG", t.TempDir())

	_, err := p.gcloudADCLogin(context.Background(), sdkplugin.LoginRequest{})
	assert.Error(t, err)
}

func TestGetGcloudADCToken_Cached(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	adcDir := t.TempDir()
	t.Setenv("CLOUDSDK_CONFIG", adcDir)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	adcCreds := GcloudADCCredentials{
		ClientID:     "gcloud-client-id",
		ClientSecret: "gcloud-client-secret",
		RefreshToken: "gcloud-refresh-token",
		Type:         "authorized_user",
	}
	adcBytes, _ := json.Marshal(adcCreds)
	require.NoError(t, os.WriteFile(adcDir+"/application_default_credentials.json", adcBytes, 0o600))

	scope := "cloud-platform"
	fingerprint := fingerprintHash("gcloud-client-id")
	cacheKey := buildCacheKey(auth.FlowGcloudADC, fingerprint, scope)
	entry := tokenCacheEntry{
		AccessToken: "cached-gcloud-at",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
		CachedAt:    time.Now(),
		Flow:        auth.FlowGcloudADC,
	}
	data, _ := json.Marshal(entry)
	fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(data)

	token, err := p.getGcloudADCToken(context.Background(), scope, false)
	require.NoError(t, err)
	assert.Equal(t, "cached-gcloud-at", token.AccessToken)
}

func TestGetGcloudADCToken_Refresh(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	adcDir := t.TempDir()
	t.Setenv("CLOUDSDK_CONFIG", adcDir)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	adcCreds := GcloudADCCredentials{
		ClientID:     "gcloud-client-id",
		ClientSecret: "gcloud-client-secret",
		RefreshToken: "gcloud-refresh-token",
		Type:         "authorized_user",
	}
	adcBytes, _ := json.Marshal(adcCreds)
	require.NoError(t, os.WriteFile(adcDir+"/application_default_credentials.json", adcBytes, 0o600))

	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken: "refreshed-at",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})

	token, err := p.getGcloudADCToken(context.Background(), "cloud-platform", true)
	require.NoError(t, err)
	assert.Equal(t, "refreshed-at", token.AccessToken)
}

func TestLoadGcloudADCCredentials(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("CLOUDSDK_CONFIG", dir)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

		creds := GcloudADCCredentials{
			ClientID:     "cid",
			ClientSecret: "cs",
			RefreshToken: "rt",
			Type:         "authorized_user",
		}
		data, _ := json.Marshal(creds)
		require.NoError(t, os.WriteFile(dir+"/application_default_credentials.json", data, 0o600))

		loaded, err := LoadGcloudADCCredentials()
		require.NoError(t, err)
		assert.Equal(t, "cid", loaded.ClientID)
	})

	t.Run("wrong type", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("CLOUDSDK_CONFIG", dir)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

		creds := GcloudADCCredentials{Type: "service_account"}
		data, _ := json.Marshal(creds)
		require.NoError(t, os.WriteFile(dir+"/application_default_credentials.json", data, 0o600))

		_, err := LoadGcloudADCCredentials()
		assert.ErrorIs(t, err, ErrNoGcloudADCConfigured)
	})

	t.Run("no file", func(t *testing.T) {
		t.Setenv("CLOUDSDK_CONFIG", t.TempDir())
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

		_, err := LoadGcloudADCCredentials()
		assert.ErrorIs(t, err, ErrNoGcloudADCConfigured)
	})

	t.Run("empty refresh token", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("CLOUDSDK_CONFIG", dir)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

		creds := GcloudADCCredentials{
			ClientID: "cid",
			Type:     "authorized_user",
		}
		data, _ := json.Marshal(creds)
		require.NoError(t, os.WriteFile(dir+"/application_default_credentials.json", data, 0o600))

		_, err := LoadGcloudADCCredentials()
		assert.ErrorIs(t, err, ErrNoGcloudADCConfigured)
	})
}

func TestGetGcloudADCPath(t *testing.T) {
	t.Run("from CLOUDSDK_CONFIG", func(t *testing.T) {
		t.Setenv("CLOUDSDK_CONFIG", "/custom/config")
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		path := getGcloudADCPath()
		assert.Contains(t, path, "/custom/config/application_default_credentials.json")
	})

	t.Run("from GOOGLE_APPLICATION_CREDENTIALS", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/path/to/creds.json")
		path := getGcloudADCPath()
		assert.Equal(t, "/path/to/creds.json", path)
	})
}

func TestGetServiceAccountKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := dir + "/sa-key.json"
		key := ServiceAccountKey{
			Type:         "service_account",
			ProjectID:    "my-project",
			PrivateKeyID: "key-id",
			ClientEmail:  "sa@project.iam.gserviceaccount.com",
			ClientID:     "12345",
		}
		data, _ := json.Marshal(key)
		require.NoError(t, os.WriteFile(keyFile, data, 0o600))
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyFile)

		loaded, err := GetServiceAccountKey()
		require.NoError(t, err)
		assert.Equal(t, "sa@project.iam.gserviceaccount.com", loaded.ClientEmail)
		assert.Equal(t, "my-project", loaded.ProjectID)
	})

	t.Run("wrong type", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := dir + "/creds.json"
		creds := map[string]string{"type": "authorized_user"}
		data, _ := json.Marshal(creds)
		require.NoError(t, os.WriteFile(keyFile, data, 0o600))
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyFile)

		_, err := GetServiceAccountKey()
		assert.ErrorIs(t, err, ErrNoServiceAccountConfigured)
	})

	t.Run("no env var", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		_, err := GetServiceAccountKey()
		assert.ErrorIs(t, err, ErrNoServiceAccountConfigured)
	})

	t.Run("file not found", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/path.json")
		_, err := GetServiceAccountKey()
		assert.Error(t, err)
		assert.NotErrorIs(t, err, ErrNoServiceAccountConfigured)
	})
}

func TestServiceAccountStatus_WithKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := dir + "/sa-key.json"
	key := ServiceAccountKey{
		Type:        "service_account",
		ClientEmail: "sa@project.iam.gserviceaccount.com",
		ClientID:    "12345",
	}
	data, _ := json.Marshal(key)
	require.NoError(t, os.WriteFile(keyFile, data, 0o600))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyFile)

	p, _, _ := newTestPlugin(t)
	status, err := p.serviceAccountStatus(context.Background())
	require.NoError(t, err)
	assert.True(t, status.Authenticated)
	assert.Equal(t, auth.IdentityTypeServicePrincipal, status.IdentityType)
	assert.Equal(t, "sa@project.iam.gserviceaccount.com", status.Claims.Email)
}

func TestWorkloadIdentityStatus(t *testing.T) {
	t.Run("no config", func(t *testing.T) {
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
		p, _, _ := newTestPlugin(t)
		status, err := p.workloadIdentityStatus(context.Background())
		require.NoError(t, err)
		assert.False(t, status.Authenticated)
	})

	t.Run("with config", func(t *testing.T) {
		dir := t.TempDir()
		configFile := dir + "/external.json"
		cfg := ExternalAccountConfig{
			Type:             "external_account",
			Audience:         "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
			CredentialSource: CredentialSource{File: "/dev/null"},
		}
		data, _ := json.Marshal(cfg)
		require.NoError(t, os.WriteFile(configFile, data, 0o600))
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", configFile)

		p, _, _ := newTestPlugin(t)
		status, err := p.workloadIdentityStatus(context.Background())
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Contains(t, status.TokenFile, "/dev/null")
	})
}

func TestReadSubjectToken(t *testing.T) {
	t.Run("plain text file", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := dir + "/token"
		require.NoError(t, os.WriteFile(tokenFile, []byte("my-subject-token"), 0o600))

		cfg := &ExternalAccountConfig{
			CredentialSource: CredentialSource{File: tokenFile},
		}
		token, err := readSubjectToken(cfg)
		require.NoError(t, err)
		assert.Equal(t, "my-subject-token", token)
	})

	t.Run("JSON file", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := dir + "/token.json"
		tokenDoc := map[string]string{"access_token": "json-token"}
		data, _ := json.Marshal(tokenDoc)
		require.NoError(t, os.WriteFile(tokenFile, data, 0o600))

		cfg := &ExternalAccountConfig{
			CredentialSource: CredentialSource{
				File: tokenFile,
				Format: &CredentialSourceFormat{
					Type:                  "json",
					SubjectTokenFieldName: "access_token",
				},
			},
		}
		token, err := readSubjectToken(cfg)
		require.NoError(t, err)
		assert.Equal(t, "json-token", token)
	})

	t.Run("JSON file default field", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := dir + "/token.json"
		tokenDoc := map[string]string{"token": "default-field-token"}
		data, _ := json.Marshal(tokenDoc)
		require.NoError(t, os.WriteFile(tokenFile, data, 0o600))

		cfg := &ExternalAccountConfig{
			CredentialSource: CredentialSource{
				File:   tokenFile,
				Format: &CredentialSourceFormat{Type: "json"},
			},
		}
		token, err := readSubjectToken(cfg)
		require.NoError(t, err)
		assert.Equal(t, "default-field-token", token)
	})

	t.Run("JSON file missing field", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := dir + "/token.json"
		tokenDoc := map[string]string{"other": "value"}
		data, _ := json.Marshal(tokenDoc)
		require.NoError(t, os.WriteFile(tokenFile, data, 0o600))

		cfg := &ExternalAccountConfig{
			CredentialSource: CredentialSource{
				File:   tokenFile,
				Format: &CredentialSourceFormat{Type: "json", SubjectTokenFieldName: "missing"},
			},
		}
		_, err := readSubjectToken(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("no file or URL", func(t *testing.T) {
		cfg := &ExternalAccountConfig{
			CredentialSource: CredentialSource{},
		}
		_, err := readSubjectToken(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported credential source")
	})

	t.Run("file not found", func(t *testing.T) {
		cfg := &ExternalAccountConfig{
			CredentialSource: CredentialSource{File: "/nonexistent/token"},
		}
		_, err := readSubjectToken(cfg)
		assert.Error(t, err)
	})
}

func TestGetExternalAccountConfig(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		dir := t.TempDir()
		configFile := dir + "/external.json"
		cfg := ExternalAccountConfig{
			Type:             "external_account",
			Audience:         "aud",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		}
		data, _ := json.Marshal(cfg)
		require.NoError(t, os.WriteFile(configFile, data, 0o600))
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", configFile)

		loaded, err := GetExternalAccountConfig()
		require.NoError(t, err)
		assert.Equal(t, "aud", loaded.Audience)
	})

	t.Run("wrong type", func(t *testing.T) {
		dir := t.TempDir()
		configFile := dir + "/external.json"
		cfg := map[string]string{"type": "authorized_user"}
		data, _ := json.Marshal(cfg)
		require.NoError(t, os.WriteFile(configFile, data, 0o600))
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", configFile)

		_, err := GetExternalAccountConfig()
		assert.ErrorIs(t, err, ErrNoWorkloadIdentityConfigured)
	})

	t.Run("env not set", func(t *testing.T) {
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
		_, err := GetExternalAccountConfig()
		assert.ErrorIs(t, err, ErrNoWorkloadIdentityConfigured)
	})

	t.Run("file not found", func(t *testing.T) {
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "/nonexistent.json")
		_, err := GetExternalAccountConfig()
		assert.Error(t, err)
	})
}

func TestMetadataHelpers(t *testing.T) {
	t.Run("getMetadataHost default", func(t *testing.T) {
		t.Setenv("GCE_METADATA_HOST", "")
		assert.Equal(t, defaultMetadataHost, getMetadataHost())
	})

	t.Run("getMetadataHost override with allowed host", func(t *testing.T) {
		t.Setenv("GCE_METADATA_HOST", "localhost:8080")
		assert.Equal(t, "localhost:8080", getMetadataHost())
	})

	t.Run("getMetadataHost override with disallowed host", func(t *testing.T) {
		t.Setenv("GCE_METADATA_HOST", "evil-host:8080")
		assert.Equal(t, defaultMetadataHost, getMetadataHost())
	})

	t.Run("getMetadataTokenURL", func(t *testing.T) {
		t.Setenv("GCE_METADATA_HOST", "")
		u := getMetadataTokenURL()
		assert.Contains(t, u, "computeMetadata/v1/instance/service-accounts/default/token")
	})

	t.Run("getMetadataEmailURL", func(t *testing.T) {
		t.Setenv("GCE_METADATA_HOST", "")
		u := getMetadataEmailURL()
		assert.Contains(t, u, "computeMetadata/v1/instance/service-accounts/default/email")
	})
}

func TestMetadataLogin_WithTestServer(t *testing.T) {
	// Start a test HTTP server that mimics the metadata server
	mux := http.NewServeMux()
	mux.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(metadataFlavorHeader) != metadataFlavorValue {
			http.Error(w, "missing metadata header", http.StatusForbidden)
			return
		}
		resp := MetadataTokenResponse{
			AccessToken: "metadata-at",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(metadataFlavorHeader) != metadataFlavorValue {
			http.Error(w, "missing metadata header", http.StatusForbidden)
			return
		}
		_, _ = fmt.Fprint(w, "sa@project.iam.gserviceaccount.com")
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Point metadata to our test server
	host := strings.TrimPrefix(ts.URL, "http://")
	t.Setenv("GCE_METADATA_HOST", host)

	p, _, _ := newTestPlugin(t)

	resp, err := p.metadataLogin(context.Background(), sdkplugin.LoginRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp.Claims)
	assert.Equal(t, "sa@project.iam.gserviceaccount.com", resp.Claims.Email)
}

func TestFetchMetadataToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(metadataFlavorHeader) != metadataFlavorValue {
			http.Error(w, "missing header", http.StatusForbidden)
			return
		}
		resp := MetadataTokenResponse{
			AccessToken: "meta-token",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	t.Setenv("GCE_METADATA_HOST", host)

	p, _, _ := newTestPlugin(t)
	token, err := p.fetchMetadataToken(context.Background(), "https://www.googleapis.com/auth/cloud-platform")
	require.NoError(t, err)
	assert.Equal(t, "meta-token", token.AccessToken)
	assert.Equal(t, auth.FlowMetadata, token.Flow)
	assert.Equal(t, "https://www.googleapis.com/auth/cloud-platform", token.Scope)
}

func TestFetchMetadataEmail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "test@project.iam.gserviceaccount.com")
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	t.Setenv("GCE_METADATA_HOST", host)

	p, _, _ := newTestPlugin(t)
	email, err := p.fetchMetadataEmail(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test@project.iam.gserviceaccount.com", email)
}

func TestGetMetadataToken_Cached(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	scope := "cloud-platform"
	cacheKey := buildCacheKey(auth.FlowMetadata, fingerprintHash(""), scope)
	entry := tokenCacheEntry{
		AccessToken: "cached-meta",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
		CachedAt:    time.Now(),
		Flow:        auth.FlowMetadata,
	}
	data, _ := json.Marshal(entry)
	fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(data)

	token, err := p.getMetadataToken(context.Background(), scope, false)
	require.NoError(t, err)
	assert.Equal(t, "cached-meta", token.AccessToken)
}

func TestIsMetadataServerAvailable(t *testing.T) {
	t.Run("available", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(200)
		}))
		defer ts.Close()

		host := strings.TrimPrefix(ts.URL, "http://")
		t.Setenv("GCE_METADATA_HOST", host)

		p, _, _ := newTestPlugin(t)
		assert.True(t, p.isMetadataServerAvailable(context.Background()))
	})

	t.Run("unavailable", func(t *testing.T) {
		t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")
		p, _, _ := newTestPlugin(t)
		assert.False(t, p.isMetadataServerAvailable(context.Background()))
	})
}

func TestNewMetadataHTTPClient(t *testing.T) {
	client := newMetadataHTTPClient(5 * time.Second)
	assert.NotNil(t, client)
	assert.Equal(t, 5*time.Second, client.Timeout)
}

func TestLogin_AllFlows(t *testing.T) {
	t.Run("workload identity flow", func(t *testing.T) {
		p, _, mockHTTP := newTestPlugin(t)

		// Create external account config
		dir := t.TempDir()
		tokenFile := dir + "/token"
		require.NoError(t, os.WriteFile(tokenFile, []byte("subject-token"), 0o600))

		configFile := dir + "/external.json"
		cfg := ExternalAccountConfig{
			Type:             "external_account",
			Audience:         "aud",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
			CredentialSource: CredentialSource{File: tokenFile},
		}
		data, _ := json.Marshal(cfg)
		require.NoError(t, os.WriteFile(configFile, data, 0o600))
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", configFile)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

		mockHTTP.AddResponse(200, STSTokenResponse{
			AccessToken:     "wi-token",
			IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
			TokenType:       "Bearer",
			ExpiresIn:       3600,
		})

		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)
		assert.NotNil(t, resp.Claims)
	})

	t.Run("gcloud ADC flow", func(t *testing.T) {
		p, _, mockHTTP := newTestPlugin(t)

		dir := t.TempDir()
		t.Setenv("CLOUDSDK_CONFIG", dir)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")

		adcCreds := GcloudADCCredentials{
			ClientID:     "cid",
			ClientSecret: "cs",
			RefreshToken: "rt",
			Type:         "authorized_user",
		}
		data, _ := json.Marshal(adcCreds)
		require.NoError(t, os.WriteFile(dir+"/application_default_credentials.json", data, 0o600))

		mockHTTP.AddResponse(200, TokenResponse{
			AccessToken: "gcloud-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})

		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowGcloudADC,
		}, nil)
		require.NoError(t, err)
		assert.NotNil(t, resp.Claims)
	})
}

func TestAcquireSourceToken_Fallbacks(t *testing.T) {
	t.Run("no credentials", func(t *testing.T) {
		p, _, _ := newTestPlugin(t)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
		t.Setenv("CLOUDSDK_CONFIG", t.TempDir())
		t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")

		_, err := p.acquireSourceToken(context.Background(), "cloud-platform", false)
		assert.ErrorIs(t, err, ErrNotAuthenticated)
	})

	t.Run("with stored refresh token", func(t *testing.T) {
		p, fake, mockHTTP := newTestPlugin(t)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
		t.Setenv("CLOUDSDK_CONFIG", t.TempDir())

		fake.secrets[SecretKeyRefreshToken] = "rt"
		meta := &TokenMetadata{
			Claims: &auth.Claims{Issuer: "https://accounts.google.com"},
			Flow:   auth.FlowInteractive,
		}
		metaBytes, _ := json.Marshal(meta)
		fake.secrets[SecretKeyMetadata] = string(metaBytes)

		mockHTTP.AddResponse(200, TokenResponse{
			AccessToken: "refreshed",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})

		token, err := p.acquireSourceToken(context.Background(), "cloud-platform", false)
		require.NoError(t, err)
		assert.Equal(t, "refreshed", token.AccessToken)
	})
}

// BenchmarkExtractClaimsFromIDToken benchmarks JWT claim extraction.
func BenchmarkExtractClaimsFromIDToken(b *testing.B) {
	payload := map[string]any{
		"iss":   "https://accounts.google.com",
		"sub":   "1234567890",
		"email": "user@example.com",
		"name":  "Test User",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	payloadBytes, _ := json.Marshal(payload)
	idToken := "h." + base64.RawURLEncoding.EncodeToString(payloadBytes) + ".s"

	b.ResetTimer()
	for range b.N {
		_, _ = extractClaimsFromIDToken(idToken)
	}
}

// generateTestRSAKey generates a PEM-encoded RSA private key for testing.
func generateTestRSAKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

func TestServiceAccountLogin_WithKey(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	dir := t.TempDir()
	keyFile := dir + "/sa-key.json"
	key := ServiceAccountKey{
		Type:         "service_account",
		ProjectID:    "test-project",
		PrivateKeyID: "key-123",
		PrivateKey:   generateTestRSAKey(t),
		ClientEmail:  "sa@test-project.iam.gserviceaccount.com",
		ClientID:     "999",
		TokenURI:     tokenEndpoint,
	}
	data, _ := json.Marshal(key)
	require.NoError(t, os.WriteFile(keyFile, data, 0o600))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyFile)
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")

	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken: "sa-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})

	resp, err := p.serviceAccountLogin(context.Background(), sdkplugin.LoginRequest{
		Scopes: []string{"cloud-platform"},
	})
	require.NoError(t, err)
	assert.Equal(t, "sa@test-project.iam.gserviceaccount.com", resp.Claims.Email)
}

func TestAcquireServiceAccountToken(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	key := &ServiceAccountKey{
		Type:         "service_account",
		ProjectID:    "test-project",
		PrivateKeyID: "key-123",
		PrivateKey:   generateTestRSAKey(t),
		ClientEmail:  "sa@test-project.iam.gserviceaccount.com",
		ClientID:     "999",
	}

	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken: "acquired-sa-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})

	token, err := p.acquireServiceAccountToken(context.Background(), key, "cloud-platform")
	require.NoError(t, err)
	assert.Equal(t, "acquired-sa-token", token.AccessToken)
	assert.Equal(t, auth.FlowServicePrincipal, token.Flow)
}

func TestAcquireServiceAccountToken_InvalidKey(t *testing.T) {
	p, _, _ := newTestPlugin(t)

	key := &ServiceAccountKey{
		PrivateKey: "not-a-valid-pem-key",
	}

	_, err := p.acquireServiceAccountToken(context.Background(), key, "cloud-platform")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse service account private key")
}

func TestAcquireServiceAccountToken_TokenError(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	key := &ServiceAccountKey{
		PrivateKey:   generateTestRSAKey(t),
		ClientEmail:  "sa@test.iam.gserviceaccount.com",
		PrivateKeyID: "key-1",
	}

	mockHTTP.AddResponse(400, TokenErrorResponse{
		Error:            "invalid_grant",
		ErrorDescription: "Key revoked",
	})

	_, err := p.acquireServiceAccountToken(context.Background(), key, "cloud-platform")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account token request failed")
}

func TestGetServiceAccountToken_Cached(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	dir := t.TempDir()
	keyFile := dir + "/sa-key.json"
	key := ServiceAccountKey{
		Type:         "service_account",
		PrivateKey:   generateTestRSAKey(t),
		ClientEmail:  "sa@test.iam.gserviceaccount.com",
		ClientID:     "999",
		PrivateKeyID: "key-1",
	}
	data, _ := json.Marshal(key)
	require.NoError(t, os.WriteFile(keyFile, data, 0o600))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyFile)

	scope := "cloud-platform"
	fingerprint := fingerprintHash("sa@test.iam.gserviceaccount.com")
	cacheKey := buildCacheKey(auth.FlowServicePrincipal, fingerprint, scope)
	entry := tokenCacheEntry{
		AccessToken: "cached-sa-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
		CachedAt:    time.Now(),
		Flow:        auth.FlowServicePrincipal,
	}
	entryData, _ := json.Marshal(entry)
	fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(entryData)

	token, err := p.getServiceAccountToken(context.Background(), scope, false)
	require.NoError(t, err)
	assert.Equal(t, "cached-sa-token", token.AccessToken)
}

func TestGetServiceAccountToken_Fresh(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	dir := t.TempDir()
	keyFile := dir + "/sa-key.json"
	key := ServiceAccountKey{
		Type:         "service_account",
		PrivateKey:   generateTestRSAKey(t),
		ClientEmail:  "sa@test.iam.gserviceaccount.com",
		ClientID:     "999",
		PrivateKeyID: "key-1",
	}
	data, _ := json.Marshal(key)
	require.NoError(t, os.WriteFile(keyFile, data, 0o600))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyFile)

	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken: "fresh-sa-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})

	token, err := p.getServiceAccountToken(context.Background(), "cloud-platform", true)
	require.NoError(t, err)
	assert.Equal(t, "fresh-sa-token", token.AccessToken)
}

func TestGetWorkloadIdentityToken_Cached(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	dir := t.TempDir()
	tokenFile := dir + "/token"
	require.NoError(t, os.WriteFile(tokenFile, []byte("subject-token"), 0o600))

	configFile := dir + "/external.json"
	cfg := ExternalAccountConfig{
		Type:             "external_account",
		Audience:         "aud://test",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		CredentialSource: CredentialSource{File: tokenFile},
	}
	cfgData, _ := json.Marshal(cfg)
	require.NoError(t, os.WriteFile(configFile, cfgData, 0o600))
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", configFile)

	scope := "cloud-platform"
	fingerprint := fingerprintHash("aud://test")
	cacheKey := buildCacheKey(auth.FlowWorkloadIdentity, fingerprint, scope)
	entry := tokenCacheEntry{
		AccessToken: "cached-wi-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
		CachedAt:    time.Now(),
		Flow:        auth.FlowWorkloadIdentity,
	}
	entryData, _ := json.Marshal(entry)
	fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(entryData)

	token, err := p.getWorkloadIdentityToken(context.Background(), scope, false)
	require.NoError(t, err)
	assert.Equal(t, "cached-wi-token", token.AccessToken)
}

func TestGetWorkloadIdentityToken_Fresh(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	dir := t.TempDir()
	tokenFile := dir + "/token"
	require.NoError(t, os.WriteFile(tokenFile, []byte("subject-token"), 0o600))

	configFile := dir + "/external.json"
	cfg := ExternalAccountConfig{
		Type:             "external_account",
		Audience:         "aud://test",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		CredentialSource: CredentialSource{File: tokenFile},
	}
	cfgData, _ := json.Marshal(cfg)
	require.NoError(t, os.WriteFile(configFile, cfgData, 0o600))
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", configFile)

	mockHTTP.AddResponse(200, STSTokenResponse{
		AccessToken:     "fresh-wi-token",
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		TokenType:       "Bearer",
		ExpiresIn:       3600,
	})

	token, err := p.getWorkloadIdentityToken(context.Background(), "cloud-platform", true)
	require.NoError(t, err)
	assert.Equal(t, "fresh-wi-token", token.AccessToken)
}

func TestDefaultHTTPClient_New(t *testing.T) {
	// Verify the DefaultHTTPClient can be created without error.
	// We don't test actual HTTP calls here because httpc blocks
	// localhost (SSRF protection). The HTTPClient interface is
	// tested via MockHTTPClient in all other tests.
	client := NewDefaultHTTPClient(logr.Discard())
	assert.NotNil(t, client)
}

func TestGetMetadataToken_Fresh(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/token", func(w http.ResponseWriter, _ *http.Request) {
		resp := MetadataTokenResponse{
			AccessToken: "fresh-meta-token",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	t.Setenv("GCE_METADATA_HOST", host)

	p, _, _ := newTestPlugin(t)
	token, err := p.getMetadataToken(context.Background(), "cloud-platform", true)
	require.NoError(t, err)
	assert.Equal(t, "fresh-meta-token", token.AccessToken)
}

func TestLogin_MetadataFlow(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/token", func(w http.ResponseWriter, _ *http.Request) {
		resp := MetadataTokenResponse{
			AccessToken: "meta-at",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "gce-sa@project.iam.gserviceaccount.com")
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	t.Setenv("GCE_METADATA_HOST", host)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")

	p, _, _ := newTestPlugin(t)
	resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
		Flow: auth.FlowMetadata,
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "gce-sa@project.iam.gserviceaccount.com", resp.Claims.Email)
}

func TestLogin_ServiceAccountFlow(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	dir := t.TempDir()
	keyFile := dir + "/sa-key.json"
	key := ServiceAccountKey{
		Type:         "service_account",
		PrivateKey:   generateTestRSAKey(t),
		ClientEmail:  "sa@proj.iam.gserviceaccount.com",
		ClientID:     "111",
		PrivateKeyID: "key-1",
	}
	keyData, _ := json.Marshal(key)
	require.NoError(t, os.WriteFile(keyFile, keyData, 0o600))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyFile)
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")

	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken: "sa-at",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})

	resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
		Flow: auth.FlowServicePrincipal,
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "sa@proj.iam.gserviceaccount.com", resp.Claims.Email)
}

func TestMockHTTPClient_AddError(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddError(fmt.Errorf("network failure"))

	_, err := mock.PostForm(context.Background(), "http://example.com", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network failure")
}

func TestAcquireWorkloadIdentityToken_Error(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	cfg := &ExternalAccountConfig{
		Audience:         "aud",
		SubjectTokenType: "jwt",
		CredentialSource: CredentialSource{},
	}

	// This should fail because no file or URL in credential source
	_, err := p.acquireWorkloadIdentityToken(context.Background(), cfg, "cloud-platform")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reading subject token")

	// Now test with valid subject token but STS error
	dir := t.TempDir()
	tokenFile := dir + "/token"
	require.NoError(t, os.WriteFile(tokenFile, []byte("sub-token"), 0o600))
	cfg.CredentialSource.File = tokenFile

	mockHTTP.AddResponse(400, TokenErrorResponse{
		Error:            "invalid_request",
		ErrorDescription: "bad audience",
	})

	_, err = p.acquireWorkloadIdentityToken(context.Background(), cfg, "cloud-platform")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "STS token exchange failed")
}

func TestGetStatus_GcloudADCFallback_TokenError(t *testing.T) {
	p, _, _ := newTestPlugin(t)

	// Set up gcloud ADC credentials
	dir := t.TempDir()
	adcFile := dir + "/application_default_credentials.json"
	creds := GcloudADCCredentials{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RefreshToken: "test-refresh-token",
		Type:         "authorized_user",
	}
	data, _ := json.Marshal(creds)
	require.NoError(t, os.WriteFile(adcFile, data, 0o600))
	t.Setenv("CLOUDSDK_CONFIG", dir)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")

	// GetStatus no longer probes gcloud ADC tokens; it reports authenticated
	// based on the presence of gcloud ADC credentials.
	status, err := p.GetStatus(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.True(t, status.Authenticated)
}

func TestGetStatus_GcloudADCFallback_InvalidGrant(t *testing.T) {
	p, _, _ := newTestPlugin(t)

	dir := t.TempDir()
	adcFile := dir + "/application_default_credentials.json"
	creds := GcloudADCCredentials{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RefreshToken: "test-refresh-token",
		Type:         "authorized_user",
	}
	data, _ := json.Marshal(creds)
	require.NoError(t, os.WriteFile(adcFile, data, 0o600))
	t.Setenv("CLOUDSDK_CONFIG", dir)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")

	// GetStatus no longer probes gcloud ADC tokens; it reports authenticated
	// based on the presence of gcloud ADC credentials.
	status, err := p.GetStatus(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.True(t, status.Authenticated)
}

func TestGetStatus_GcloudADCFallback_Success(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	dir := t.TempDir()
	adcFile := dir + "/application_default_credentials.json"
	creds := GcloudADCCredentials{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RefreshToken: "test-refresh-token",
		Type:         "authorized_user",
	}
	data, _ := json.Marshal(creds)
	require.NoError(t, os.WriteFile(adcFile, data, 0o600))
	t.Setenv("CLOUDSDK_CONFIG", dir)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")

	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})

	status, err := p.GetStatus(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.True(t, status.Authenticated)
	assert.Equal(t, "gcloud ADC (application default credentials)", status.Claims.Name)
}

func TestGetStatus_StoredRefreshToken_InvalidRAPT(t *testing.T) {
	p, fake, mockHTTP := newTestPlugin(t)

	metadata := &TokenMetadata{
		Claims: &auth.Claims{
			Issuer: "https://accounts.google.com",
			Email:  "user@example.com",
		},
		Flow:      auth.FlowInteractive,
		Scopes:    []string{"openid"},
		SessionID: "test-session",
	}
	metaBytes, _ := json.Marshal(metadata)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)
	fake.secrets[SecretKeyRefreshToken] = "test-refresh-token"

	// Mock token refresh with invalid_rapt error
	mockHTTP.AddResponse(400, TokenErrorResponse{
		Error:            "invalid_grant",
		ErrorDescription: "invalid_rapt token",
	})

	status, err := p.GetStatus(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.False(t, status.Authenticated)
	assert.Equal(t, "expired (RAPT policy)", status.Reason)
}

func TestGetStatus_StoredRefreshToken_GenericFailure(t *testing.T) {
	p, fake, mockHTTP := newTestPlugin(t)

	metadata := &TokenMetadata{
		Claims: &auth.Claims{
			Issuer: "https://accounts.google.com",
			Email:  "user@example.com",
		},
		Flow:      auth.FlowInteractive,
		Scopes:    []string{"openid"},
		SessionID: "test-session",
	}
	metaBytes, _ := json.Marshal(metadata)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)
	fake.secrets[SecretKeyRefreshToken] = "test-refresh-token"

	// Mock a generic error
	mockHTTP.AddResponse(500, TokenErrorResponse{
		Error:            "server_error",
		ErrorDescription: "internal error",
	})

	status, err := p.GetStatus(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.False(t, status.Authenticated)
	assert.Equal(t, "token refresh failed", status.Reason)
}

func TestRequestGCPDeviceCode_Error(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	mockHTTP.AddResponse(403, TokenErrorResponse{
		Error:            "access_denied",
		ErrorDescription: "device code not enabled",
	})

	_, err := p.requestGCPDeviceCode(context.Background(), "test-client-id", []string{"openid"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device code request failed")
	assert.Contains(t, err.Error(), "access_denied")
}

func TestPollGCPDeviceToken_SlowDown(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	// First poll: slow_down
	mockHTTP.AddResponse(200, map[string]string{
		"error": "slow_down",
	})
	// Second poll: success
	mockHTTP.AddResponse(200, TokenResponse{
		AccessToken: "access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})

	deviceCode := &DeviceCodeResponse{
		DeviceCode: "dc",
		Interval:   1,
	}

	resp, err := p.pollGCPDeviceToken(context.Background(), deviceCode, "client-id", "client-secret")
	require.NoError(t, err)
	assert.Equal(t, "access-token", resp.AccessToken)
}

func TestPollGCPDeviceToken_ExpiredToken(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	mockHTTP.AddResponse(200, map[string]string{
		"error": "expired_token",
	})

	deviceCode := &DeviceCodeResponse{
		DeviceCode: "dc",
		Interval:   1,
	}

	_, err := p.pollGCPDeviceToken(context.Background(), deviceCode, "client-id", "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrTimeout)
}

func TestPollGCPDeviceToken_AccessDenied(t *testing.T) {
	p, _, mockHTTP := newTestPlugin(t)

	mockHTTP.AddResponse(200, map[string]string{
		"error": "access_denied",
	})

	deviceCode := &DeviceCodeResponse{
		DeviceCode: "dc",
		Interval:   1,
	}

	_, err := p.pollGCPDeviceToken(context.Background(), deviceCode, "client-id", "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserCancelled)
}

func TestConfigValidation_MissingAt(t *testing.T) {
	cfg := &Config{
		ImpersonateServiceAccount: "sa-without-at-sign",
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "impersonateServiceAccount")
}

func TestGetStatus_CorruptedMetadata(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
	t.Setenv("CLOUDSDK_CONFIG", t.TempDir())

	fake.secrets[SecretKeyMetadata] = "not-valid-json{{"

	status, err := p.GetStatus(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.False(t, status.Authenticated)
}

func TestGetStatus_ServicePrincipalFlow(t *testing.T) {
	p, fake, _ := newTestPlugin(t)

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT", "")
	t.Setenv("CLOUDSDK_CONFIG", t.TempDir())

	metadata := &TokenMetadata{
		Claims: &auth.Claims{
			Issuer:  "https://accounts.google.com",
			Subject: "sa@project.iam.gserviceaccount.com",
			Email:   "sa@project.iam.gserviceaccount.com",
		},
		Flow:                      auth.FlowServicePrincipal,
		ImpersonateServiceAccount: "target@project.iam.gserviceaccount.com",
	}
	metaBytes, _ := json.Marshal(metadata)
	fake.secrets[SecretKeyMetadata] = string(metaBytes)

	status, err := p.GetStatus(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.True(t, status.Authenticated)
	assert.Equal(t, auth.IdentityTypeServicePrincipal, status.IdentityType)
	assert.Equal(t, "target@project.iam.gserviceaccount.com", status.ClientID)
}
