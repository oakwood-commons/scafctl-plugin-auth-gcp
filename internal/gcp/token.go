// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// TokenMetadata stores information about the stored GCP credentials.
type TokenMetadata struct {
	Claims                    *auth.Claims `json:"claims"`
	RefreshTokenExpiresAt     time.Time    `json:"refreshTokenExpiresAt,omitempty"`
	Flow                      auth.Flow    `json:"flow"`
	ClientID                  string       `json:"clientId,omitempty"`
	Project                   string       `json:"project,omitempty"`
	ImpersonateServiceAccount string       `json:"impersonateServiceAccount,omitempty"`
	Scopes                    []string     `json:"scopes,omitempty"`
	SessionID                 string       `json:"sessionId,omitempty"`
}

// TokenResponse represents the response from GCP token endpoints.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`  //nolint:gosec // G117: not a hardcoded credential, stores runtime token data
	RefreshToken string `json:"refresh_token"` //nolint:gosec // G117: not a hardcoded credential, stores runtime token data
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
}

// TokenErrorResponse represents an error from GCP token endpoint.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// tokenCacheEntry is the JSON representation stored in the host secret store.
type tokenCacheEntry struct {
	AccessToken string    `json:"accessToken"` //nolint:gosec // Not a credential, JSON field name
	TokenType   string    `json:"tokenType"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Scope       string    `json:"scope,omitempty"`
	CachedAt    time.Time `json:"cachedAt"`
	Flow        auth.Flow `json:"flow,omitempty"`
	SessionID   string    `json:"sessionId,omitempty"`
}

// fingerprintHash produces a stable hash for cache key partitioning.
func fingerprintHash(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:8])
}

// storeCredentials securely stores the refresh token and metadata via HostService.
// clientID is the effective OAuth client ID used for the login (not necessarily p.config.ClientID).
func (p *Plugin) storeCredentials(ctx context.Context, tokenResp *TokenResponse, flow auth.Flow, scopes []string, sessionID string, clientID string) error {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	// Store refresh token if present (ADC browser flow)
	if tokenResp.RefreshToken != "" {
		if err := hostClient.SetSecret(ctx, SecretKeyRefreshToken, tokenResp.RefreshToken); err != nil {
			return fmt.Errorf("failed to store refresh token: %w", err)
		}
	}

	// Extract claims
	claims, err := extractClaims(tokenResp)
	if err != nil {
		claims = &auth.Claims{
			Issuer: "https://accounts.google.com",
		}
	}

	// Generate a new session ID on initial login; preserve across rotations.
	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	metadata := &TokenMetadata{
		Claims:                    claims,
		Flow:                      flow,
		ClientID:                  clientID,
		Project:                   p.config.Project,
		ImpersonateServiceAccount: p.config.ImpersonateServiceAccount,
		Scopes:                    scopes,
		SessionID:                 sessionID,
	}

	if tokenResp.RefreshToken != "" {
		// Refresh tokens don't have a fixed expiry from Google, but
		// they can be revoked. We set a long expiry for display purposes.
		metadata.RefreshTokenExpiresAt = time.Now().Add(180 * 24 * time.Hour)
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := hostClient.SetSecret(ctx, SecretKeyMetadata, string(metadataBytes)); err != nil {
		return fmt.Errorf("failed to store metadata: %w", err)
	}

	return nil
}

// storeMetadataOnly stores metadata without a refresh token (for SA/WI/metadata flows).
func (p *Plugin) storeMetadataOnly(ctx context.Context, claims *auth.Claims, flow auth.Flow, scopes []string) error {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	metadata := &TokenMetadata{
		Claims:                    claims,
		Flow:                      flow,
		Project:                   p.config.Project,
		ImpersonateServiceAccount: p.config.ImpersonateServiceAccount,
		Scopes:                    scopes,
		SessionID:                 uuid.New().String(),
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := hostClient.SetSecret(ctx, SecretKeyMetadata, string(metadataBytes)); err != nil {
		return fmt.Errorf("failed to store metadata: %w", err)
	}

	return nil
}

// loadRefreshToken loads the stored refresh token from the host secret store.
func (p *Plugin) loadRefreshToken(ctx context.Context) (string, error) {
	return p.getSecret(ctx, SecretKeyRefreshToken)
}

// loadMetadata loads the stored token metadata from the host secret store.
func (p *Plugin) loadMetadata(ctx context.Context) (*TokenMetadata, error) {
	raw, err := p.getSecret(ctx, SecretKeyMetadata)
	if err != nil {
		return nil, err
	}

	var metadata TokenMetadata
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &metadata, nil
}

// getSecret retrieves a secret value from the host secret store.
func (p *Plugin) getSecret(ctx context.Context, key string) (string, error) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return "", fmt.Errorf("host service not available")
	}

	value, found, err := hostClient.GetSecret(ctx, key)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("secret not found: %s", key)
	}
	return value, nil
}

// secretExists checks if a secret exists in the host secret store.
func (p *Plugin) secretExists(ctx context.Context, key string) bool {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return false
	}

	_, found, err := hostClient.GetSecret(ctx, key)
	return err == nil && found
}

// extractClaims extracts normalized claims from a GCP token response.
// Uses the ID token (JWT) if available.
func extractClaims(tokenResp *TokenResponse) (*auth.Claims, error) {
	if tokenResp.IDToken == "" {
		return &auth.Claims{
			Issuer: "https://accounts.google.com",
		}, nil
	}

	return extractClaimsFromIDToken(tokenResp.IDToken)
}

// extractClaimsFromIDToken extracts claims from a GCP ID token JWT.
func extractClaimsFromIDToken(idToken string) (*auth.Claims, error) {
	parts := strings.SplitN(idToken, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid ID token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ID token payload: %w", err)
	}

	var idTokenClaims struct {
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
	}

	if err := json.Unmarshal(payload, &idTokenClaims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	username := ""
	if idTokenClaims.Email != "" {
		if idx := strings.Index(idTokenClaims.Email, "@"); idx > 0 {
			username = idTokenClaims.Email[:idx]
		}
	}

	return &auth.Claims{
		Issuer:   idTokenClaims.Issuer,
		Subject:  idTokenClaims.Subject,
		Email:    idTokenClaims.Email,
		Name:     idTokenClaims.Name,
		Username: username,
		IssuedAt: time.Unix(idTokenClaims.IssuedAt, 0),
	}, nil
}

// cacheGet retrieves a cached token from the host secret store.
func cacheGet(ctx context.Context, hostClient *sdkplugin.HostServiceClient, cacheKey string) (*auth.Token, error) {
	fullKey := SecretKeyTokenPrefix + cacheKey
	value, found, err := hostClient.GetSecret(ctx, fullKey)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	var entry tokenCacheEntry
	if err := json.Unmarshal([]byte(value), &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached token: %w", err)
	}

	return &auth.Token{
		AccessToken: entry.AccessToken,
		TokenType:   entry.TokenType,
		ExpiresAt:   entry.ExpiresAt,
		Scope:       entry.Scope,
		CachedAt:    entry.CachedAt,
		Flow:        entry.Flow,
		SessionID:   entry.SessionID,
	}, nil
}

// cacheSet stores a token in the host secret store cache.
func cacheSet(ctx context.Context, hostClient *sdkplugin.HostServiceClient, cacheKey string, token *auth.Token) error {
	entry := tokenCacheEntry{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresAt:   token.ExpiresAt,
		Scope:       token.Scope,
		CachedAt:    time.Now(),
		Flow:        token.Flow,
		SessionID:   token.SessionID,
	}

	data, err := json.Marshal(entry) //nolint:gosec // intentional: caching token data in host secret store
	if err != nil {
		return fmt.Errorf("failed to marshal token for caching: %w", err)
	}

	return hostClient.SetSecret(ctx, SecretKeyTokenPrefix+cacheKey, string(data))
}

// cacheClear removes all cached tokens from the host secret store.
func cacheClear(ctx context.Context, lgr logr.Logger, hostClient *sdkplugin.HostServiceClient) {
	keys, err := hostClient.ListSecrets(ctx, SecretKeyTokenPrefix+"*")
	if err != nil {
		lgr.V(1).Info("failed to list cached tokens", "error", err)
		return
	}
	for _, key := range keys {
		if err := hostClient.DeleteSecret(ctx, key); err != nil {
			lgr.V(1).Info("failed to delete cached token", "key", key, "error", err)
		}
	}
}

// cacheListEntries lists all cached token entries.
func cacheListEntries(ctx context.Context, hostClient *sdkplugin.HostServiceClient) ([]*auth.CachedTokenInfo, error) {
	keys, err := hostClient.ListSecrets(ctx, SecretKeyTokenPrefix+"*")
	if err != nil {
		return nil, err
	}

	var results []*auth.CachedTokenInfo
	for _, key := range keys {
		value, found, err := hostClient.GetSecret(ctx, key)
		if err != nil || !found {
			continue
		}

		var entry tokenCacheEntry
		if err := json.Unmarshal([]byte(value), &entry); err != nil {
			continue
		}

		scope := entry.Scope
		if scope == "" {
			scope = strings.TrimPrefix(key, SecretKeyTokenPrefix)
		}
		results = append(results, &auth.CachedTokenInfo{
			Handler:   HandlerName,
			TokenKind: "access",
			TokenType: entry.TokenType,
			Scope:     scope,
			Flow:      entry.Flow,
			ExpiresAt: entry.ExpiresAt,
			CachedAt:  entry.CachedAt,
			IsExpired: !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt),
			SessionID: entry.SessionID,
		})
	}

	return results, nil
}

// cachePurgeExpired removes expired tokens and returns the count removed.
func cachePurgeExpired(ctx context.Context, hostClient *sdkplugin.HostServiceClient) (int, error) {
	keys, err := hostClient.ListSecrets(ctx, SecretKeyTokenPrefix+"*")
	if err != nil {
		return 0, err
	}

	count := 0
	for _, key := range keys {
		value, found, err := hostClient.GetSecret(ctx, key)
		if err != nil || !found {
			continue
		}

		var entry tokenCacheEntry
		if err := json.Unmarshal([]byte(value), &entry); err != nil {
			continue
		}

		if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
			if err := hostClient.DeleteSecret(ctx, key); err == nil {
				count++
			}
		}
	}

	return count, nil
}

// buildCacheKey constructs a cache key from flow, fingerprint, and scope.
func buildCacheKey(flow auth.Flow, fingerprint, scope string) string {
	raw := string(flow) + ":" + fingerprint + ":" + scope
	h := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
