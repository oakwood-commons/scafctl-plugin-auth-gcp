// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// defaultCredentialCleanupTimeout bounds detached rollback/cleanup RPCs on the
// host secret store so a stalled host never blocks Login or callback settlement
// indefinitely.
const defaultCredentialCleanupTimeout = 5 * time.Second

// errInconsistentSession indicates stored session metadata and its bound
// refresh token do not match (e.g. partial external edit or corrupted store).
var errInconsistentSession = errors.New("stored session credentials are inconsistent")

// errMetadataNotFound indicates no stored session metadata exists for the profile.
var errMetadataNotFound = errors.New("stored session metadata not found")

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
	RefreshTokenID            string       `json:"refreshTokenId,omitempty"`
	RefreshTokenHash          string       `json:"refreshTokenSha256,omitempty"`
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

func (p *Plugin) newCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	p.mu.RLock()
	timeout := p.cleanupTimeout
	p.mu.RUnlock()
	if timeout <= 0 {
		timeout = defaultCredentialCleanupTimeout
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

func (p *Plugin) versionedRefreshKey(ctx context.Context, revID string) string {
	return p.secretKey(ctx, secretSuffixRefreshToken+"."+revID)
}

// storeCredentials securely stores the refresh token and metadata via HostService.
// clientID is the effective OAuth client ID used for the login.
func (p *Plugin) storeCredentials(ctx context.Context, tokenResp *TokenResponse, flow auth.Flow, scopes []string, sessionID string, clientID string) error {
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return err
	}
	_, err = p.storeCredentialsWithClaims(ctx, cfg, tokenResp, flow, scopes, sessionID, clientID, nil)
	return err
}

// storeCredentialsWithClaims stores the refresh token and metadata under the
// profile write lock and returns the committed SessionID.
func (p *Plugin) storeCredentialsWithClaims(ctx context.Context, cfg *Config, tokenResp *TokenResponse, flow auth.Flow, scopes []string, sessionID string, clientID string, preExtractedClaims *auth.Claims) (string, error) {
	mu := p.profileLock(ctx)
	mu.Lock()
	defer mu.Unlock()

	return p.storeCredentialsLocked(ctx, cfg, tokenResp, flow, scopes, sessionID, clientID, preExtractedClaims)
}

// storeCredentialsAndSeedToken atomically commits session credentials, clears
// stale cached access tokens for the profile, and seeds initialToken (stamped
// with the committed SessionID) inside one profile write-lock critical section.
func (p *Plugin) storeCredentialsAndSeedToken(ctx context.Context, cfg *Config, tokenResp *TokenResponse, flow auth.Flow, scopes []string, sessionID string, clientID string, preExtractedClaims *auth.Claims, initialCacheKey string, initialToken *auth.Token) (string, error) {
	mu := p.profileLock(ctx)
	mu.Lock()
	defer mu.Unlock()

	committedSessionID, err := p.storeCredentialsLocked(ctx, cfg, tokenResp, flow, scopes, sessionID, clientID, preExtractedClaims)
	if err != nil {
		return "", err
	}

	if hostClient := p.hostClient(ctx); hostClient != nil {
		lgr := logr.FromContextOrDiscard(ctx)
		prefix := p.tokenCachePrefix(ctx)
		cacheClearWithPrefix(ctx, lgr, hostClient, prefix)
		if initialToken != nil && initialCacheKey != "" && initialToken.AccessToken != "" {
			seeded := *initialToken
			seeded.SessionID = committedSessionID
			if err := cacheSetWithPrefix(ctx, hostClient, prefix, initialCacheKey, &seeded); err != nil {
				lgr.V(1).Info("failed to seed initial access token", "error", err)
			}
		}
	}

	return committedSessionID, nil
}

// storeRotatedCredentials updates stored credentials for a refresh-token
// rotation only if expectedMeta.SessionID is still the active session,
// preserving the session's Project and ImpersonateServiceAccount fields.
func (p *Plugin) storeRotatedCredentials(ctx context.Context, cfg *Config, tokenResp *TokenResponse, expectedMeta *TokenMetadata, clientID string) error {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	mu := p.profileLock(ctx)
	mu.Lock()
	defer mu.Unlock()

	curMetaRaw, found, err := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixMetadata))
	if err != nil {
		return fmt.Errorf("failed to inspect current session metadata: %w", err)
	}
	if !found {
		return nil
	}
	var curMeta TokenMetadata
	if parseErr := json.Unmarshal([]byte(curMetaRaw), &curMeta); parseErr != nil || curMeta.SessionID != expectedMeta.SessionID {
		return nil
	}

	preservedCfg := DefaultConfig()
	if cfg != nil {
		*preservedCfg = *cfg
	}
	preservedCfg.Project = expectedMeta.Project
	preservedCfg.ImpersonateServiceAccount = expectedMeta.ImpersonateServiceAccount

	_, err = p.storeCredentialsLocked(ctx, preservedCfg, tokenResp, expectedMeta.Flow, expectedMeta.Scopes, expectedMeta.SessionID, clientID, expectedMeta.Claims)
	return err
}

func (p *Plugin) storeCredentialsLocked(ctx context.Context, cfg *Config, tokenResp *TokenResponse, flow auth.Flow, scopes []string, sessionID string, clientID string, preExtractedClaims *auth.Claims) (string, error) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return "", fmt.Errorf("host service not available")
	}

	if cfg == nil {
		cfg = p.baseConfig()
	}

	claims := preExtractedClaims
	if claims == nil {
		var err error
		claims, err = extractClaims(tokenResp)
		if err != nil {
			claims = &auth.Claims{
				Issuer: "https://accounts.google.com",
			}
		}
	}

	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	metadata := &TokenMetadata{
		Claims:                    claims,
		Flow:                      flow,
		ClientID:                  clientID,
		Project:                   cfg.Project,
		ImpersonateServiceAccount: cfg.ImpersonateServiceAccount,
		Scopes:                    scopes,
		SessionID:                 sessionID,
	}

	var revID string
	if tokenResp.RefreshToken != "" {
		revID = uuid.New().String()
		metadata.RefreshTokenExpiresAt = time.Now().Add(180 * 24 * time.Hour)
		metadata.RefreshTokenID = revID
		metadata.RefreshTokenHash = fingerprintHash(tokenResp.RefreshToken)
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}
	metadataRaw := string(metadataBytes)

	legacyRefreshKey := p.secretKey(ctx, secretSuffixRefreshToken)
	metadataKey := p.secretKey(ctx, secretSuffixMetadata)

	prevMetaRaw, hadPrevMeta, prevMetaErr := hostClient.GetSecret(ctx, metadataKey)
	var prevRevID string
	if prevMetaErr == nil && hadPrevMeta {
		var prevMeta TokenMetadata
		if pErr := json.Unmarshal([]byte(prevMetaRaw), &prevMeta); pErr == nil {
			prevRevID = prevMeta.RefreshTokenID
		}
	}

	if tokenResp.RefreshToken != "" {
		verRefreshKey := p.versionedRefreshKey(ctx, revID)
		// 1. Write the new refresh token under a unique revision key first so no
		// existing or concurrent login's refresh token is overwritten before
		// metadata commits.
		if err := hostClient.SetSecret(ctx, verRefreshKey, tokenResp.RefreshToken); err != nil {
			return "", fmt.Errorf("failed to store refresh token: %w", err)
		}

		// 2. Single forward commit point: write metadata pointing at verRefreshKey
		// and its SHA-256 fingerprint. On failure, delete our unreferenced
		// verRefreshKey under a bounded cleanup timeout.
		if err := hostClient.SetSecret(ctx, metadataKey, metadataRaw); err != nil {
			cleanupCtx, cleanupCancel := p.newCleanupContext(ctx)
			defer cleanupCancel()
			_ = hostClient.DeleteSecret(cleanupCtx, verRefreshKey)
			return "", fmt.Errorf("failed to store metadata: %w", err)
		}

		// 3. Best-effort mirror to legacyRefreshKey for backward compatibility.
		if err := hostClient.SetSecret(ctx, legacyRefreshKey, tokenResp.RefreshToken); err != nil {
			logr.FromContextOrDiscard(ctx).V(1).Info("warning: failed to mirror refresh token to legacy secret key", "error", err)
		}
	} else {
		if err := hostClient.SetSecret(ctx, metadataKey, metadataRaw); err != nil {
			return "", fmt.Errorf("failed to store metadata: %w", err)
		}
		cleanupCtx, cleanupCancel := p.newCleanupContext(ctx)
		defer cleanupCancel()
		_ = hostClient.DeleteSecret(cleanupCtx, legacyRefreshKey)
	}

	// 4. Garbage-collect the specific revision superseded by this write if it
	// is no longer referenced by metadataKey.
	if prevRevID != "" && prevRevID != revID {
		cleanupCtx, cleanupCancel := p.newCleanupContext(ctx)
		defer cleanupCancel()
		if curMetaRaw, curFound, curErr := hostClient.GetSecret(cleanupCtx, metadataKey); curErr == nil && curFound {
			var curMeta TokenMetadata
			if pErr := json.Unmarshal([]byte(curMetaRaw), &curMeta); pErr == nil && curMeta.RefreshTokenID != prevRevID {
				_ = hostClient.DeleteSecret(cleanupCtx, p.versionedRefreshKey(ctx, prevRevID))
			}
		}
	}

	return sessionID, nil
}

// storeMetadataOnly stores metadata without a refresh token (for SA/WI/metadata/gcloud_adc flows).
func (p *Plugin) storeMetadataOnly(ctx context.Context, claims *auth.Claims, flow auth.Flow, scopes []string) error {
	_, err := p.storeMetadataWithInitialToken(ctx, claims, flow, scopes, false, "", nil)
	return err
}

// storeMetadataAndSeedToken atomically commits metadata, clears stale cached
// tokens for the profile, and seeds initialToken (stamped with the committed
// SessionID) inside one profile write-lock critical section.
func (p *Plugin) storeMetadataAndSeedToken(ctx context.Context, claims *auth.Claims, flow auth.Flow, scopes []string, initialCacheKey string, initialToken *auth.Token) (string, error) {
	return p.storeMetadataWithInitialToken(ctx, claims, flow, scopes, true, initialCacheKey, initialToken)
}

func (p *Plugin) storeMetadataWithInitialToken(ctx context.Context, claims *auth.Claims, flow auth.Flow, scopes []string, clearCache bool, initialCacheKey string, initialToken *auth.Token) (string, error) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return "", fmt.Errorf("host service not available")
	}

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return "", err
	}

	mu := p.profileLock(ctx)
	mu.Lock()
	defer mu.Unlock()

	metadataKey := p.secretKey(ctx, secretSuffixMetadata)
	prevMetaRaw, hadPrevMeta, prevMetaErr := hostClient.GetSecret(ctx, metadataKey)
	var prevRevID string
	if prevMetaErr == nil && hadPrevMeta {
		var prevMeta TokenMetadata
		if pErr := json.Unmarshal([]byte(prevMetaRaw), &prevMeta); pErr == nil {
			prevRevID = prevMeta.RefreshTokenID
		}
	}

	sessionID := uuid.New().String()
	metadata := &TokenMetadata{
		Claims:                    claims,
		Flow:                      flow,
		Project:                   cfg.Project,
		ImpersonateServiceAccount: cfg.ImpersonateServiceAccount,
		Scopes:                    scopes,
		SessionID:                 sessionID,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := hostClient.SetSecret(ctx, metadataKey, string(metadataBytes)); err != nil {
		return "", fmt.Errorf("failed to store metadata: %w", err)
	}

	// Clean up any stale refresh tokens from an earlier interactive/device_code
	// session in this profile so GetStatus/GetToken do not treat this profile as
	// refresh-token-backed.
	cleanupCtx, cleanupCancel := p.newCleanupContext(ctx)
	defer cleanupCancel()
	_ = hostClient.DeleteSecret(cleanupCtx, p.secretKey(ctx, secretSuffixRefreshToken))
	if prevRevID != "" {
		_ = hostClient.DeleteSecret(cleanupCtx, p.versionedRefreshKey(ctx, prevRevID))
	}

	if clearCache {
		lgr := logr.FromContextOrDiscard(ctx)
		prefix := p.tokenCachePrefix(ctx)
		cacheClearWithPrefix(ctx, lgr, hostClient, prefix)
		if initialToken != nil && initialCacheKey != "" && initialToken.AccessToken != "" {
			seeded := *initialToken
			seeded.SessionID = sessionID
			if err := cacheSetWithPrefix(ctx, hostClient, prefix, initialCacheKey, &seeded); err != nil {
				lgr.V(1).Info("failed to seed initial access token", "error", err)
			}
		}
	}

	return sessionID, nil
}

// inspectStoredMetadataAndRefresh reads metadata and any associated refresh
// token atomically under the profile read lock.
func (p *Plugin) inspectStoredMetadataAndRefresh(ctx context.Context) (*TokenMetadata, string, bool, error) {
	mu := p.profileLock(ctx)
	mu.RLock()
	defer mu.RUnlock()

	return p.inspectStoredMetadataAndRefreshUnlocked(ctx)
}

func isRefreshTokenFlow(flow auth.Flow) bool {
	return flow == "" || flow == auth.FlowInteractive || flow == auth.FlowDeviceCode
}

func (p *Plugin) inspectStoredMetadataAndRefreshUnlocked(ctx context.Context) (*TokenMetadata, string, bool, error) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return nil, "", false, fmt.Errorf("host service not available")
	}

	metaRaw, metaFound, metaErr := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixMetadata))
	if metaErr != nil {
		return nil, "", false, metaErr
	}
	if !metaFound {
		return nil, "", false, fmt.Errorf("%w: %s", errMetadataNotFound, p.secretKey(ctx, secretSuffixMetadata))
	}

	var metadata TokenMetadata
	if err := json.Unmarshal([]byte(metaRaw), &metadata); err != nil {
		return nil, "", false, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if !isRefreshTokenFlow(metadata.Flow) {
		return &metadata, "", false, nil
	}

	var refreshToken string
	if metadata.RefreshTokenID != "" {
		verRT, verFound, verErr := hostClient.GetSecret(ctx, p.versionedRefreshKey(ctx, metadata.RefreshTokenID))
		if verErr != nil {
			return nil, "", false, verErr
		}
		if verFound && verRT != "" {
			refreshToken = verRT
		}
	}

	if refreshToken == "" {
		legacyRT, legacyFound, legacyErr := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixRefreshToken))
		if legacyErr != nil {
			return nil, "", false, legacyErr
		}
		if legacyFound && legacyRT != "" {
			refreshToken = legacyRT
		}
	}

	// When metadata bound a specific refresh token hash, require a matching token.
	if metadata.RefreshTokenHash != "" {
		if refreshToken == "" || fingerprintHash(refreshToken) != metadata.RefreshTokenHash {
			return nil, "", false, errInconsistentSession
		}
		return &metadata, refreshToken, true, nil
	}

	if refreshToken != "" {
		return &metadata, refreshToken, true, nil
	}

	return &metadata, "", false, nil
}

// loadSessionCredentials atomically loads a refresh-token-backed session
// (refresh token + metadata) for mintToken.
func (p *Plugin) loadSessionCredentials(ctx context.Context) (string, *TokenMetadata, error) {
	metadata, refreshToken, hasRefresh, err := p.inspectStoredMetadataAndRefresh(ctx)
	if err != nil {
		if errors.Is(err, errInconsistentSession) {
			return "", nil, fmt.Errorf("%w: %w", ErrNotAuthenticated, err)
		}
		return "", nil, ErrNotAuthenticated
	}
	if !hasRefresh || refreshToken == "" {
		return "", nil, ErrNotAuthenticated
	}
	return refreshToken, metadata, nil
}

func (p *Plugin) loadRefreshTokenStatus(ctx context.Context) (bool, *TokenMetadata) {
	mu := p.profileLock(ctx)
	mu.RLock()
	defer mu.RUnlock()

	if metadata, _, hasRefresh, err := p.inspectStoredMetadataAndRefreshUnlocked(ctx); err == nil && hasRefresh {
		return true, metadata
	}
	return false, nil
}

// readFlowSessionID returns the stored SessionID when the profile's stored
// metadata matches expectedFlow, or "" otherwise.
func (p *Plugin) readFlowSessionID(ctx context.Context, expectedFlow auth.Flow) string {
	metadata, err := p.loadMetadata(ctx)
	if err != nil || metadata == nil || metadata.Flow != expectedFlow {
		return ""
	}
	return metadata.SessionID
}

// cacheTokenForSession writes token into the profile's token cache under the
// profile read lock after verifying that any non-empty token.SessionID still
// matches the profile's active SessionID (preventing stale mints from
// resurrecting tokens after Logout or overwriting a replacement Login).
func (p *Plugin) cacheTokenForSession(ctx context.Context, cacheKey string, token *auth.Token) {
	if token == nil || token.AccessToken == "" {
		return
	}
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return
	}

	mu := p.profileLock(ctx)
	mu.RLock()
	defer mu.RUnlock()

	if token.SessionID != "" {
		metaRaw, found, err := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixMetadata))
		if err != nil || !found || metaRaw == "" {
			return
		}
		var curMeta TokenMetadata
		if parseErr := json.Unmarshal([]byte(metaRaw), &curMeta); parseErr != nil || curMeta.SessionID != token.SessionID {
			return
		}
	}

	if cacheSetErr := cacheSetWithPrefix(ctx, hostClient, p.tokenCachePrefix(ctx), cacheKey, token); cacheSetErr != nil {
		logr.FromContextOrDiscard(ctx).V(1).Info("failed to cache token", "error", cacheSetErr)
	}
}

// loadRefreshToken loads the stored refresh token from the host secret store,
// preferring the metadata-bound versioned secret when session metadata exists.
func (p *Plugin) loadRefreshToken(ctx context.Context) (string, error) {
	mu := p.profileLock(ctx)
	mu.RLock()
	defer mu.RUnlock()

	if _, rt, hasRefresh, err := p.inspectStoredMetadataAndRefreshUnlocked(ctx); err == nil && hasRefresh {
		return rt, nil
	}
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return "", fmt.Errorf("host service not available")
	}
	if _, metaFound, metaErr := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixMetadata)); metaErr == nil && !metaFound {
		return p.getSecret(ctx, p.secretKey(ctx, secretSuffixRefreshToken))
	}
	return "", fmt.Errorf("stored session credentials are missing or inconsistent")
}

// loadMetadata loads the stored token metadata from the host secret store.
func (p *Plugin) loadMetadata(ctx context.Context) (*TokenMetadata, error) {
	mu := p.profileLock(ctx)
	mu.RLock()
	defer mu.RUnlock()

	raw, err := p.getSecret(ctx, p.secretKey(ctx, secretSuffixMetadata))
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

	issuer := idTokenClaims.Issuer
	if issuer == "" {
		issuer = "https://accounts.google.com"
	}

	return &auth.Claims{
		Issuer:   issuer,
		Subject:  idTokenClaims.Subject,
		Email:    idTokenClaims.Email,
		Name:     idTokenClaims.Name,
		Username: username,
		IssuedAt: time.Unix(idTokenClaims.IssuedAt, 0),
	}, nil
}

func tokenPrefixFromContext(ctx context.Context) string {
	profile := auth.ProfileFromContext(ctx)
	if profile == "" {
		return SecretKeyTokenPrefix
	}
	return secretKeyBase + "." + hex.EncodeToString([]byte(profile)) + "." + secretSuffixTokenPrefix
}

// cacheGet retrieves a cached token from the host secret store for ctx's profile.
func cacheGet(ctx context.Context, hostClient *sdkplugin.HostServiceClient, cacheKey string) (*auth.Token, error) {
	return cacheGetWithPrefix(ctx, hostClient, tokenPrefixFromContext(ctx), cacheKey)
}

func cacheGetWithPrefix(ctx context.Context, hostClient *sdkplugin.HostServiceClient, prefix, cacheKey string) (*auth.Token, error) {
	fullKey := prefix + cacheKey
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

// cacheSet stores a token in the host secret store cache for ctx's profile.
func cacheSet(ctx context.Context, hostClient *sdkplugin.HostServiceClient, cacheKey string, token *auth.Token) error {
	return cacheSetWithPrefix(ctx, hostClient, tokenPrefixFromContext(ctx), cacheKey, token)
}

func cacheSetWithPrefix(ctx context.Context, hostClient *sdkplugin.HostServiceClient, prefix, cacheKey string, token *auth.Token) error {
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

	return hostClient.SetSecret(ctx, prefix+cacheKey, string(data))
}

// cacheClear removes all cached tokens from the host secret store for ctx's profile.
func cacheClear(ctx context.Context, lgr logr.Logger, hostClient *sdkplugin.HostServiceClient) {
	cacheClearWithPrefix(ctx, lgr, hostClient, tokenPrefixFromContext(ctx))
}

func cacheClearWithPrefix(ctx context.Context, lgr logr.Logger, hostClient *sdkplugin.HostServiceClient, prefix string) {
	keys, err := hostClient.ListSecrets(ctx, prefix+"*")
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

// cacheListEntries lists all cached token entries for ctx's profile.
func cacheListEntries(ctx context.Context, hostClient *sdkplugin.HostServiceClient) ([]*auth.CachedTokenInfo, error) {
	return cacheListEntriesWithPrefix(ctx, hostClient, tokenPrefixFromContext(ctx))
}

func cacheListEntriesWithPrefix(ctx context.Context, hostClient *sdkplugin.HostServiceClient, prefix string) ([]*auth.CachedTokenInfo, error) {
	keys, err := hostClient.ListSecrets(ctx, prefix+"*")
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
			scope = strings.TrimPrefix(key, prefix)
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

// cachePurgeExpired removes expired tokens for ctx's profile and returns the count removed.
func cachePurgeExpired(ctx context.Context, hostClient *sdkplugin.HostServiceClient) (int, error) {
	return cachePurgeExpiredWithPrefix(ctx, hostClient, tokenPrefixFromContext(ctx))
}

func cachePurgeExpiredWithPrefix(ctx context.Context, hostClient *sdkplugin.HostServiceClient, prefix string) (int, error) {
	keys, err := hostClient.ListSecrets(ctx, prefix+"*")
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
// Scopes are normalized (canonicalized and sorted) so that equivalent scope sets
// always produce the same cache key regardless of input ordering or alias form.
func buildCacheKey(flow auth.Flow, fingerprint, scope string) string {
	raw := string(flow) + ":" + fingerprint + ":" + normalizeScope(scope)
	h := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// googleScopeAliases maps short OpenID Connect scope aliases to their canonical
// long-form Google URLs. Google's token endpoint returns long forms regardless
// of which form was requested.
var googleScopeAliases = map[string]string{
	"email":   "https://www.googleapis.com/auth/userinfo.email",
	"profile": "https://www.googleapis.com/auth/userinfo.profile",
}

// normalizeScope canonicalizes, de-duplicates, and sorts a space-separated scope
// string so that equivalent sets (differing only in order, alias form, or
// repeated entries) always produce identical output.
func normalizeScope(scope string) string {
	parts := strings.Fields(scope)
	seen := make(map[string]struct{}, len(parts))
	uniq := parts[:0]
	for _, s := range parts {
		if canonical, ok := googleScopeAliases[s]; ok {
			s = canonical
		}
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			uniq = append(uniq, s)
		}
	}
	slices.Sort(uniq)
	return strings.Join(uniq, " ")
}
