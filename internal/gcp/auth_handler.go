// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package gcp implements the GCP auth handler plugin for scafctl.
package gcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/httpc"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"

	"github.com/oakwood-commons/scafctl-plugin-auth-gcp/internal/clock"
)

const (
	// HandlerName is the unique identifier for this auth handler.
	HandlerName = "gcp"

	// HandlerDisplayName is the human-readable name for the handler.
	HandlerDisplayName = "Google Cloud Platform"

	// Version is the auth handler version.
	Version = "0.1.0"

	secretKeyBase            = "scafctl.auth.gcp" //nolint:gosec // key namespace, not a credential
	secretSuffixRefreshToken = "refresh_token"
	secretSuffixMetadata     = "metadata"
	secretSuffixTokenPrefix  = "token."

	// SecretKeyRefreshToken is the secret key for storing the default-profile refresh token.
	SecretKeyRefreshToken = secretKeyBase + "." + secretSuffixRefreshToken //nolint:gosec // key name, not a credential

	// SecretKeyMetadata is the secret key for storing default-profile token metadata.
	SecretKeyMetadata = secretKeyBase + "." + secretSuffixMetadata //nolint:gosec // key name, not a credential

	// SecretKeyTokenPrefix is the prefix for default-profile cached access tokens.
	SecretKeyTokenPrefix = secretKeyBase + "." + secretSuffixTokenPrefix //nolint:gosec // key prefix, not a credential

	// DefaultTimeout is the default timeout for browser OAuth flow.
	DefaultTimeout = 5 * time.Minute

	// DefaultMinValidFor is the minimum remaining validity for a cached token.
	DefaultMinValidFor = 5 * time.Minute
)

// BrowserOpenFunc is the signature for a function that opens a URL in the browser.
type BrowserOpenFunc func(ctx context.Context, url string) error

var _ sdkplugin.AuthHandlerPlugin = (*Plugin)(nil)

// Plugin implements the scafctl AuthHandlerPlugin interface.
type Plugin struct {
	mu               sync.RWMutex
	cfg              sdkplugin.ProviderConfig
	config           *Config
	httpClient       HTTPClient
	clock            clock.Clock
	cachedHostClient *sdkplugin.HostServiceClient
	openBrowser      BrowserOpenFunc

	profileLocks   sync.Map
	cleanupTimeout time.Duration

	clientCacheMu   sync.Mutex
	clientCacheSize int
	baseLogger      logr.Logger
	initHTTPKey     effectiveHTTPConfigKey
	hasInitHTTPKey  bool
	httpClientCache *boundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient]
}

// profileLock returns the profile-scoped RWMutex coordinating in-process
// credential reads, commits, rotations, and logouts without blocking other
// profiles or holding locks across external HTTP/browser I/O.
func (p *Plugin) profileLock(ctx context.Context) *sync.RWMutex {
	profile := auth.ProfileFromContext(ctx)
	if v, ok := p.profileLocks.Load(profile); ok {
		return v.(*sync.RWMutex)
	}
	mu := &sync.RWMutex{}
	actual, _ := p.profileLocks.LoadOrStore(profile, mu)
	return actual.(*sync.RWMutex)
}

type resolvedConfigKeyType struct{}

func withResolvedConfig(ctx context.Context, cfg *Config) context.Context {
	return context.WithValue(ctx, resolvedConfigKeyType{}, cfg)
}

func resolvedConfigFromContext(ctx context.Context) (*Config, bool) {
	cfg, ok := ctx.Value(resolvedConfigKeyType{}).(*Config)
	return cfg, ok && cfg != nil
}

func attachRequestSettings(ctx context.Context, reqSettings map[string]json.RawMessage) context.Context {
	if _, ok := sdkplugin.RequestSettingsFromContext(ctx); !ok && reqSettings != nil {
		return sdkplugin.WithRequestSettings(ctx, reqSettings)
	}
	return ctx
}

func (p *Plugin) baseConfig() *Config {
	p.mu.RLock()
	cfg := p.config
	p.mu.RUnlock()
	if cfg != nil {
		return cfg
	}
	return DefaultConfig()
}

func extractHandlerSettingsJSON(settings map[string]json.RawMessage) ([]byte, error) {
	if nested, hasHandler := settings[HandlerName]; hasHandler {
		if !bytes.Equal(bytes.TrimSpace(nested), []byte("null")) {
			return nested, nil
		}
		return nil, nil
	}
	if len(settings) > 0 {
		raw, err := json.Marshal(settings)
		if err != nil {
			return nil, fmt.Errorf("failed to encode request settings: %w", err)
		}
		return raw, nil
	}
	return nil, nil
}

// effectiveConfig returns the handler Config for ctx: per-RPC request settings
// from RequestSettingsFromContext(ctx) when present, falling back to the
// ConfigureAuthHandler config without mutating p.config.
func (p *Plugin) effectiveConfig(ctx context.Context) (*Config, error) {
	if cfg, ok := resolvedConfigFromContext(ctx); ok {
		return cfg, nil
	}
	if settings, ok := sdkplugin.RequestSettingsFromContext(ctx); ok {
		raw, err := extractHandlerSettingsJSON(settings)
		if err != nil {
			return nil, err
		}
		return parseHandlerConfig(raw)
	}
	return p.baseConfig(), nil
}

func pickHTTPLogger(ctx context.Context, baseLogger logr.Logger) logr.Logger {
	if baseLogger.GetSink() != nil {
		return baseLogger.V(5)
	}
	return logr.FromContextOrDiscard(ctx).V(5)
}

func (p *Plugin) ensureHTTPClientCacheLocked() *boundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient] {
	if p.httpClientCache == nil {
		p.httpClientCache = newBoundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient](p.clientCacheSize)
	}
	return p.httpClientCache
}

func (p *Plugin) httpClientForConfig(ctx context.Context, cfg *Config) (HTTPClient, error) {
	var appCfg *httpc.AppConfig
	if cfg != nil {
		appCfg = cfg.HTTPClient
	}

	key, clientCfg, err := resolveEffectiveHTTPConfig(appCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP client from httpClient config: %w", err)
	}

	p.clientCacheMu.Lock()
	curHTTP := p.httpClient
	hasInit := p.hasInitHTTPKey
	initKey := p.initHTTPKey
	baseLgr := p.baseLogger
	if curHTTP != nil {
		if _, isDefault := curHTTP.(*DefaultHTTPClient); !isDefault {
			p.clientCacheMu.Unlock()
			return curHTTP, nil
		}
		if hasInit && key == initKey {
			p.clientCacheMu.Unlock()
			return curHTTP, nil
		}
	}
	cache := p.ensureHTTPClientCacheLocked()
	p.clientCacheMu.Unlock()

	return cache.GetOrCreate(key, func() *DefaultHTTPClient {
		return newDefaultHTTPClientFromResolved(clientCfg, pickHTTPLogger(ctx, baseLgr))
	}), nil
}

func (p *Plugin) closeHTTPClients() {
	p.clientCacheMu.Lock()
	httpCache := p.httpClientCache
	curHTTP := p.httpClient
	p.httpClientCache = nil
	if _, isDefault := curHTTP.(*DefaultHTTPClient); isDefault {
		p.httpClient = nil
		p.hasInitHTTPKey = false
	}
	p.clientCacheMu.Unlock()

	if httpCache != nil {
		httpCache.CloseAll()
	}
	if defHTTP, ok := curHTTP.(*DefaultHTTPClient); ok {
		_ = defHTTP.Close()
	}
}

// GetAuthHandlers returns the list of auth handlers exposed by this plugin.
//
//nolint:revive // ctx required by interface
func (p *Plugin) GetAuthHandlers(_ context.Context) ([]sdkplugin.AuthHandlerInfo, error) {
	return []sdkplugin.AuthHandlerInfo{
		{
			Name:        HandlerName,
			DisplayName: HandlerDisplayName,
			Flows: []auth.Flow{
				auth.FlowInteractive,
				auth.FlowDeviceCode,
				auth.FlowServicePrincipal,
				auth.FlowWorkloadIdentity,
				auth.FlowMetadata,
				auth.FlowGcloudADC,
			},
			Capabilities: []auth.Capability{
				auth.CapScopesOnLogin,
				auth.CapScopesOnTokenRequest,
				auth.CapFederatedToken,
				auth.CapCallbackPort,
				auth.CapFlowOverride,
			},
		},
	}, nil
}

// ConfigureAuthHandler stores host-side configuration and initializes the handler.
func (p *Plugin) ConfigureAuthHandler(ctx context.Context, handlerName string, cfg sdkplugin.ProviderConfig) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}

	rawSettings, err := extractHandlerSettingsJSON(cfg.Settings)
	if err != nil {
		return err
	}

	parsedCfg, err := parseHandlerConfig(rawSettings)
	if err != nil {
		return err
	}

	initKey, initClientCfg, err := resolveEffectiveHTTPConfig(parsedCfg.HTTPClient)
	if err != nil {
		return fmt.Errorf("failed to build HTTP client from httpClient config: %w", err)
	}

	baseLgr := logr.FromContextOrDiscard(ctx)
	httpLogger := baseLgr.V(5) // high verbosity for auth HTTP

	p.clientCacheMu.Lock()
	needHTTP := p.httpClient == nil
	if !needHTTP {
		_, needHTTP = p.httpClient.(*DefaultHTTPClient)
	}
	p.clientCacheMu.Unlock()

	var nextHTTP *DefaultHTTPClient
	if needHTTP {
		nextHTTP = newDefaultHTTPClientFromResolved(initClientCfg, httpLogger)
	}

	p.mu.Lock()
	p.cfg = cfg
	p.config = parsedCfg
	if p.clock == nil {
		p.clock = clock.Real{}
	}
	p.cachedHostClient = sdkplugin.HostClientFromContext(ctx)
	if p.openBrowser == nil {
		p.openBrowser = defaultBrowserOpener
	}
	p.mu.Unlock()

	var prevHTTP *DefaultHTTPClient
	p.clientCacheMu.Lock()
	if nextHTTP != nil {
		if defHTTP, isDefault := p.httpClient.(*DefaultHTTPClient); isDefault {
			prevHTTP = defHTTP
		}
		if p.httpClient == nil || prevHTTP != nil {
			p.httpClient = nextHTTP
		} else {
			prevHTTP = nextHTTP
		}
	}
	oldHTTPCache := p.httpClientCache
	p.baseLogger = baseLgr
	p.initHTTPKey = initKey
	p.hasInitHTTPKey = true
	p.httpClientCache = newBoundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient](p.clientCacheSize)
	p.clientCacheMu.Unlock()

	if oldHTTPCache != nil {
		oldHTTPCache.CloseAll()
	}
	if prevHTTP != nil {
		_ = prevHTTP.Close()
	}

	return nil
}

// Login performs the authentication flow.
//
// Flow selection precedence:
//  1. WorkloadIdentity -- highest priority when configured or env credentials exist
//  2. ServicePrincipal -- when serviceAccountKeyFile or GOOGLE_APPLICATION_CREDENTIALS is set
//  3. Metadata -- when running on GCE/GKE
//  4. DeviceCode -- when explicitly requested
//  5. GcloudADC -- when explicitly requested
//  6. Interactive (ADC browser OAuth) -- default
func (p *Plugin) Login(ctx context.Context, handlerName string, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	ctx = attachRequestSettings(ctx, req.Settings)
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	switch req.Flow { //nolint:exhaustive // "" auto-detects; default falls back to interactive
	case auth.FlowWorkloadIdentity:
		return p.workloadIdentityLogin(ctx, req)
	case auth.FlowServicePrincipal:
		return p.serviceAccountLogin(ctx, req)
	case auth.FlowMetadata:
		return p.metadataLogin(ctx, req)
	case auth.FlowDeviceCode:
		return p.deviceCodeLogin(ctx, req, deviceCodeCb)
	case auth.FlowGcloudADC:
		return p.gcloudADCLogin(ctx, req)
	case "":
		if _, wiErr := p.getExternalAccountConfigForConfig(cfg); wiErr == nil {
			return p.workloadIdentityLogin(ctx, req)
		} else if !errors.Is(wiErr, ErrNoWorkloadIdentityConfigured) {
			return nil, fmt.Errorf("workload identity credentials error: %w", wiErr)
		}

		if _, saErr := p.getServiceAccountKeyForConfig(cfg); saErr == nil {
			return p.serviceAccountLogin(ctx, req)
		} else if !errors.Is(saErr, ErrNoServiceAccountConfigured) {
			return nil, fmt.Errorf("service account credentials error: %w", saErr)
		}

		if p.isMetadataServerAvailable(ctx) {
			return p.metadataLogin(ctx, req)
		}
	}

	// Default to ADC (native browser OAuth)
	return p.adcLogin(ctx, req, deviceCodeCb)
}

// Logout revokes the current session for the target profile.
func (p *Plugin) Logout(ctx context.Context, handlerName string, _ sdkplugin.LogoutRequest) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	return p.logoutInternal(ctx)
}

// logoutRevokeTimeout bounds best-effort Google refresh-token revocation during
// Logout so an unreachable revocation endpoint cannot stall Logout indefinitely.
const logoutRevokeTimeout = 10 * time.Second

// logoutInternal clears stored credentials and cached tokens for ctx's profile.
func (p *Plugin) logoutInternal(ctx context.Context) error {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("logging out", "handler", HandlerName)

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	mu := p.profileLock(ctx)

	// Snapshot active session ID and refresh token under read lock so network
	// revocation runs unlocked without racing a concurrent replacement Login.
	var rt string
	var beforeSessionID string
	mu.RLock()
	if meta, inspectedRT, hasRefresh, inspectErr := p.inspectStoredMetadataAndRefreshUnlocked(ctx); inspectErr == nil {
		beforeSessionID = meta.SessionID
		if hasRefresh {
			rt = inspectedRT
		}
	} else if errors.Is(inspectErr, errMetadataNotFound) {
		if legacyRT, legacyFound, legacyErr := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixRefreshToken)); legacyErr == nil && legacyFound {
			rt = legacyRT
		}
	}
	mu.RUnlock()

	if rt != "" {
		revokeCtx, cancel := context.WithTimeout(ctx, logoutRevokeTimeout)
		err := p.revokeRefreshTokenValue(revokeCtx, rt)
		cancel()
		if err != nil {
			lgr.V(1).Info("failed to revoke refresh token (may not exist)", "error", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()

	// If a new Login committed a different non-empty SessionID while revocation
	// was in flight, do not wipe the replacement session.
	if beforeSessionID != "" {
		if metaRaw, found, getErr := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixMetadata)); getErr == nil && found && metaRaw != "" {
			var curMeta TokenMetadata
			if parseErr := json.Unmarshal([]byte(metaRaw), &curMeta); parseErr == nil && curMeta.SessionID != "" && curMeta.SessionID != beforeSessionID {
				return nil
			}
		}
	}

	p.logoutLocked(ctx, hostClient)
	return nil
}

// logoutIfSessionMatches clears stored credentials only when the stored
// session metadata can be read and parsed and its SessionID still matches
// expectedSessionID. Returning without deleting on GetSecret errors, absent
// metadata, or parse failures ensures a transient read error during an old
// refresh's invalid_grant cannot wipe a newer session.
func (p *Plugin) logoutIfSessionMatches(ctx context.Context, expectedSessionID string) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return
	}

	mu := p.profileLock(ctx)
	mu.Lock()
	defer mu.Unlock()

	metaRaw, found, err := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixMetadata))
	if err != nil || !found || metaRaw == "" {
		return
	}
	var curMeta TokenMetadata
	if parseErr := json.Unmarshal([]byte(metaRaw), &curMeta); parseErr != nil || curMeta.SessionID != expectedSessionID {
		return
	}

	p.logoutLocked(ctx, hostClient)
}

func (p *Plugin) logoutLocked(ctx context.Context, hostClient *sdkplugin.HostServiceClient) {
	lgr := logr.FromContextOrDiscard(ctx)

	// Clear all cached tokens for this profile
	cacheClearWithPrefix(ctx, lgr, hostClient, p.tokenCachePrefix(ctx))

	// Delete versioned refresh tokens and legacy refresh token for this profile
	refreshKey := p.secretKey(ctx, secretSuffixRefreshToken)
	cacheClearWithPrefix(ctx, lgr, hostClient, refreshKey+".")
	if err := hostClient.DeleteSecret(ctx, refreshKey); err != nil {
		lgr.V(1).Info("failed to delete refresh token (may not exist)", "error", err)
	}

	// Delete metadata for this profile
	if err := hostClient.DeleteSecret(ctx, p.secretKey(ctx, secretSuffixMetadata)); err != nil {
		lgr.V(1).Info("failed to delete metadata (may not exist)", "error", err)
	}
}

// GetStatus returns the current authentication status without mutating stored state.
func (p *Plugin) GetStatus(ctx context.Context, handlerName string, req sdkplugin.StatusRequest) (*auth.Status, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	ctx = attachRequestSettings(ctx, req.Settings)
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	// 1. Workload identity credentials (highest priority; fail closed on invalid explicit/configured file)
	if extCfg, wiErr := p.getExternalAccountConfigForConfig(cfg); wiErr == nil {
		return p.workloadIdentityStatusFromParsed(cfg, extCfg), nil
	} else if !errors.Is(wiErr, ErrNoWorkloadIdentityConfigured) {
		return &auth.Status{
			Authenticated: false,
			Flow:          auth.FlowWorkloadIdentity,
			Reason:        wiErr.Error(),
		}, nil
	}

	// 2. Service account credentials (fail closed on invalid explicit/configured file)
	if saKey, saErr := p.getServiceAccountKeyForConfig(cfg); saErr == nil {
		return p.serviceAccountStatusFromKey(cfg, saKey), nil
	} else if !errors.Is(saErr, ErrNoServiceAccountConfigured) {
		return &auth.Status{
			Authenticated: false,
			Flow:          auth.FlowServicePrincipal,
			Reason:        saErr.Error(),
		}, nil
	}

	// 3. Stored credentials in this profile
	metadata, refreshToken, hasRefresh, credErr := p.inspectStoredMetadataAndRefresh(ctx)
	if credErr != nil {
		if errors.Is(credErr, errMetadataNotFound) {
			// 4. Ambient GCE/GKE metadata server
			if p.isMetadataServerAvailable(ctx) {
				return &auth.Status{
					Authenticated: true,
					Flow:          auth.FlowMetadata,
					ClientID:      cfg.ImpersonateServiceAccount,
					Claims: &auth.Claims{
						Issuer: "https://accounts.google.com",
						Name:   "GCE/GKE metadata server",
					},
					IdentityType: auth.IdentityTypeServicePrincipal,
				}, nil
			}

			// 5. Ambient gcloud ADC fallback
			if tokenErr := p.validateGcloudADCCredentials(ctx); tokenErr == nil {
				return &auth.Status{
					Authenticated: true,
					Flow:          auth.FlowGcloudADC,
					ClientID:      cfg.ImpersonateServiceAccount,
					Claims: &auth.Claims{
						Issuer: "https://accounts.google.com",
						Name:   "gcloud ADC (application default credentials)",
					},
					IdentityType: auth.IdentityTypeUser,
				}, nil
			} else if !errors.Is(tokenErr, ErrNotAuthenticated) {
				lgr := logr.FromContextOrDiscard(ctx)
				lgr.V(1).Info("gcloud ADC credential validation failed", "error", tokenErr)
				reason := "failed to validate gcloud ADC credentials"
				var invalidErr *gcloudADCInvalidCredentialsError
				if errors.As(tokenErr, &invalidErr) {
					reason = "gcloud ADC credentials are invalid; run 'gcloud auth application-default login' to re-authenticate"
				}
				return &auth.Status{
					Authenticated: false,
					Flow:          auth.FlowGcloudADC,
					Reason:        reason,
				}, nil
			}

			return &auth.Status{Authenticated: false}, nil
		}

		if errors.Is(credErr, errInconsistentSession) {
			return &auth.Status{
				Authenticated: false,
				Reason:        "stored session credentials are inconsistent",
			}, nil
		}
		return &auth.Status{Authenticated: false}, nil //nolint:nilerr // treat corrupted metadata as not authenticated
	}

	status := &auth.Status{
		Authenticated: true,
		Claims:        metadata.Claims,
		IdentityType:  auth.IdentityTypeUser,
		Scopes:        metadata.Scopes,
		Flow:          metadata.Flow,
	}

	switch metadata.Flow { //nolint:exhaustive // user flows default to IdentityTypeUser
	case auth.FlowServicePrincipal, auth.FlowMetadata:
		status.IdentityType = auth.IdentityTypeServicePrincipal
	case auth.FlowWorkloadIdentity:
		status.IdentityType = auth.IdentityTypeWorkloadIdentity
	}

	if !metadata.RefreshTokenExpiresAt.IsZero() {
		status.ExpiresAt = metadata.RefreshTokenExpiresAt
	}

	if _, hasReqSettings := sdkplugin.RequestSettingsFromContext(ctx); hasReqSettings {
		status.ClientID = cfg.ImpersonateServiceAccount
	} else if cfg.ImpersonateServiceAccount != "" {
		status.ClientID = cfg.ImpersonateServiceAccount
	} else if metadata.ImpersonateServiceAccount != "" {
		status.ClientID = metadata.ImpersonateServiceAccount
	}

	// Validate refresh-token-backed user sessions read-only (checking cache first,
	// then probing tokenEndpoint without persisting or wiping credentials).
	if hasRefresh {
		if tokenErr := p.validateStoredRefreshToken(ctx, cfg, metadata, refreshToken); tokenErr != nil {
			status.Authenticated = false
			errMsg := tokenErr.Error()
			switch {
			case strings.Contains(errMsg, "invalid_rapt"):
				status.Reason = "expired (RAPT policy)"
			case strings.Contains(errMsg, "invalid_grant"),
				errors.Is(tokenErr, ErrTokenExpired):
				status.Reason = "expired or revoked"
			default:
				status.Reason = "token refresh failed"
			}
		}
	} else if metadata.Flow == auth.FlowGcloudADC {
		if tokenErr := p.validateGcloudADCCredentials(ctx); tokenErr != nil {
			status.Authenticated = false
			status.Reason = "failed to validate gcloud ADC credentials"
			var invalidErr *gcloudADCInvalidCredentialsError
			if errors.As(tokenErr, &invalidErr) {
				status.Reason = "gcloud ADC credentials are invalid; run 'gcloud auth application-default login' to re-authenticate"
			}
		}
	}

	return status, nil
}

// GetToken returns a valid access token, refreshing if necessary.
func (p *Plugin) GetToken(ctx context.Context, handlerName string, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	ctx = attachRequestSettings(ctx, req.Settings)
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	scope := req.Scope
	if scope == "" {
		return nil, fmt.Errorf("scope is required")
	}

	minValidFor := req.MinValidFor
	if minValidFor <= 0 {
		minValidFor = DefaultMinValidFor
	}

	token, err := p.resolveAndAcquireTokenWithMinValidFor(ctx, scope, req.ForceRefresh, minValidFor)
	if err != nil {
		return nil, err
	}

	return &sdkplugin.TokenResponse{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresAt:   token.ExpiresAt,
		Scope:       token.Scope,
		CachedAt:    token.CachedAt,
		Flow:        token.Flow,
		SessionID:   token.SessionID,
	}, nil
}

// resolveAndAcquireToken determines the appropriate token source and acquires a token.
func (p *Plugin) resolveAndAcquireToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	return p.resolveAndAcquireTokenWithMinValidFor(ctx, scope, forceRefresh, DefaultMinValidFor)
}

func (p *Plugin) resolveAndAcquireTokenWithMinValidFor(ctx context.Context, scope string, forceRefresh bool, minValidFor time.Duration) (*auth.Token, error) {
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	// If impersonation is configured, get a source token first then impersonate
	if cfg.ImpersonateServiceAccount != "" {
		sourceToken, err := p.acquireSourceTokenWithMinValidFor(ctx, scope, forceRefresh, minValidFor)
		if err != nil {
			return nil, fmt.Errorf("acquiring source token for impersonation: %w", err)
		}
		return p.getImpersonatedTokenWithSource(ctx, sourceToken, scope, forceRefresh, minValidFor)
	}

	return p.acquireSourceTokenWithMinValidFor(ctx, scope, forceRefresh, minValidFor)
}

// acquireSourceToken determines the appropriate credential source and acquires a token.
func (p *Plugin) acquireSourceToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	return p.acquireSourceTokenWithMinValidFor(ctx, scope, forceRefresh, DefaultMinValidFor)
}

func (p *Plugin) acquireSourceTokenWithMinValidFor(ctx context.Context, scope string, forceRefresh bool, minValidFor time.Duration) (*auth.Token, error) {
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	// 1. Workload identity (highest priority; fail closed on invalid explicit/configured file)
	if _, wiErr := p.getExternalAccountConfigForConfig(cfg); wiErr == nil {
		return p.getWorkloadIdentityTokenWithMinValidFor(ctx, scope, forceRefresh, minValidFor)
	} else if !errors.Is(wiErr, ErrNoWorkloadIdentityConfigured) {
		return nil, fmt.Errorf("workload identity credentials error: %w", wiErr)
	}

	// 2. Service account key (fail closed on invalid explicit/configured file)
	if _, saErr := p.getServiceAccountKeyForConfig(cfg); saErr == nil {
		return p.getServiceAccountTokenWithMinValidFor(ctx, scope, forceRefresh, minValidFor)
	} else if !errors.Is(saErr, ErrNoServiceAccountConfigured) {
		return nil, fmt.Errorf("service account credentials error: %w", saErr)
	}

	// 3. Stored profile session (metadata, gcloud_adc, interactive, device_code)
	metadata, _, hasRefresh, credErr := p.inspectStoredMetadataAndRefresh(ctx)
	if credErr == nil && metadata != nil {
		switch {
		case metadata.Flow == auth.FlowMetadata:
			return p.getMetadataTokenWithMinValidFor(ctx, scope, forceRefresh, minValidFor)
		case metadata.Flow == auth.FlowGcloudADC:
			return p.getGcloudADCTokenWithMinValidFor(ctx, scope, forceRefresh, minValidFor)
		case hasRefresh || metadata.Flow == auth.FlowInteractive || metadata.Flow == auth.FlowDeviceCode:
			return p.getStoredRefreshTokenWithMinValidFor(ctx, scope, forceRefresh, minValidFor)
		}
	} else if errors.Is(credErr, errInconsistentSession) {
		return nil, fmt.Errorf("%w: %w", ErrNotAuthenticated, credErr)
	}

	// 4. Ambient GCE/GKE metadata server
	if p.isMetadataServerAvailable(ctx) {
		return p.getMetadataTokenWithMinValidFor(ctx, scope, forceRefresh, minValidFor)
	}

	// 5. Ambient gcloud ADC fallback
	if HasGcloudADCCredentials() {
		return p.getGcloudADCTokenWithMinValidFor(ctx, scope, forceRefresh, minValidFor)
	}

	return nil, ErrNotAuthenticated
}

// ListCachedTokens returns information about cached tokens for ctx's profile.
func (p *Plugin) ListCachedTokens(ctx context.Context, handlerName string) ([]*auth.CachedTokenInfo, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return nil, fmt.Errorf("host service not available")
	}

	var results []*auth.CachedTokenInfo

	// Refresh token (ADC browser / device code flow)
	if hasRefresh, metadata := p.loadRefreshTokenStatus(ctx); hasRefresh {
		info := &auth.CachedTokenInfo{
			Handler:   HandlerName,
			TokenKind: "refresh",
		}
		if metadata != nil {
			info.ExpiresAt = metadata.RefreshTokenExpiresAt
			info.Flow = metadata.Flow
			info.SessionID = metadata.SessionID
		}
		if !info.ExpiresAt.IsZero() {
			info.IsExpired = time.Now().After(info.ExpiresAt)
		}
		results = append(results, info)
	}

	// Minted access tokens for this profile
	entries, listErr := cacheListEntriesWithPrefix(ctx, hostClient, p.tokenCachePrefix(ctx))
	if listErr != nil {
		return nil, fmt.Errorf("listing cached tokens: %w", listErr)
	}
	results = append(results, entries...)

	return results, nil
}

// PurgeExpiredTokens removes expired tokens from ctx's profile cache.
func (p *Plugin) PurgeExpiredTokens(ctx context.Context, handlerName string) (int, error) {
	if handlerName != HandlerName {
		return 0, fmt.Errorf("unknown handler: %s", handlerName)
	}

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return 0, fmt.Errorf("host service not available")
	}

	return cachePurgeExpiredWithPrefix(ctx, hostClient, p.tokenCachePrefix(ctx))
}

// DetectAvailableFlows reports which flows have pre-existing environment or configured credentials,
// ordered to match Login / GetStatus / GetToken auto-detection precedence.
func (p *Plugin) DetectAvailableFlows(ctx context.Context, handlerName string) ([]sdkplugin.FlowAvailability, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	var flows []sdkplugin.FlowAvailability

	// 1. Workload identity
	if p.hasWorkloadIdentityCredentialsForConfig(cfg) {
		reason := "GOOGLE_EXTERNAL_ACCOUNT is set"
		if cfg.profileOrEnv(cfg.ExternalAccountFile, "externalAccountFile", "") != "" {
			reason = "externalAccountFile is configured"
		}
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowWorkloadIdentity,
			Available: true,
			Reason:    reason,
		})
	}

	// 2. Service account
	if p.hasServiceAccountCredentialsForConfig(cfg) {
		reason := "GOOGLE_APPLICATION_CREDENTIALS is set with service_account type"
		if cfg.profileOrEnv(cfg.ServiceAccountKeyFile, "serviceAccountKeyFile", "") != "" {
			reason = "serviceAccountKeyFile is configured with service_account type"
		}
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowServicePrincipal,
			Available: true,
			Reason:    reason,
		})
	}

	// 3. Metadata server -- short timeout probe
	if p.isMetadataServerAvailable(ctx) {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowMetadata,
			Available: true,
			Reason:    "GCE/GKE metadata server is reachable",
		})
	}

	// 4. gcloud ADC: validate credentials are actually usable before advertising the flow.
	adcCtx, adcCancel := context.WithTimeout(ctx, 5*time.Second)
	defer adcCancel()
	if err := p.validateGcloudADCCredentials(adcCtx); err == nil {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowGcloudADC,
			Available: true,
			Reason:    "gcloud application default credentials found",
		})
	}

	return flows, nil
}

// StopAuthHandler performs cleanup for the named handler.
func (p *Plugin) StopAuthHandler(_ context.Context, handlerName string) error {
	if handlerName != "" && handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	p.closeHTTPClients()
	return nil
}

// hostClient returns the HostServiceClient, preferring the one from context.
func (p *Plugin) hostClient(ctx context.Context) *sdkplugin.HostServiceClient {
	if hc := sdkplugin.HostClientFromContext(ctx); hc != nil {
		return hc
	}
	p.mu.RLock()
	hc := p.cachedHostClient
	p.mu.RUnlock()
	return hc
}

// binaryName returns the binary name from config or a default.
func (p *Plugin) binaryName() string {
	p.mu.RLock()
	name := p.cfg.BinaryName
	p.mu.RUnlock()
	if name != "" {
		return name
	}
	return "scafctl"
}

func (p *Plugin) callbackPages() *sdkplugin.AuthCallbackPages {
	p.mu.RLock()
	pages := p.cfg.AuthCallbackPages
	p.mu.RUnlock()
	return pages
}

func (p *Plugin) browserOpener() BrowserOpenFunc {
	p.mu.RLock()
	opener := p.openBrowser
	p.mu.RUnlock()
	if opener != nil {
		return opener
	}
	return defaultBrowserOpener
}

func (p *Plugin) getClock() clock.Clock {
	p.mu.RLock()
	clk := p.clock
	p.mu.RUnlock()
	if clk != nil {
		return clk
	}
	return clock.Real{}
}

// secretKey returns a profile-scoped secret key. An empty context profile
// always maps to the default (unscoped) key format -- never back-filled from
// ConfigureAuthHandler's p.cfg.Profile -- because the host resolves the active
// profile before the gRPC call when the active session is intended. Profile
// names are hex-encoded to prevent dot-delimited namespace collisions.
func (p *Plugin) secretKey(ctx context.Context, suffix string) string {
	profile := auth.ProfileFromContext(ctx)
	if profile == "" {
		return secretKeyBase + "." + suffix
	}
	return secretKeyBase + "." + hex.EncodeToString([]byte(profile)) + "." + suffix
}

// tokenCachePrefix returns the profile-scoped prefix for cached access tokens.
func (p *Plugin) tokenCachePrefix(ctx context.Context) string {
	return p.secretKey(ctx, secretSuffixTokenPrefix)
}

// validateStoredRefreshToken checks whether a stored refresh-token session is
// valid without mutating stored credentials or cached tokens.
func (p *Plugin) validateStoredRefreshToken(ctx context.Context, cfg *Config, metadata *TokenMetadata, refreshToken string) error {
	storedClientID := metadata.ClientID
	if storedClientID == "" {
		storedClientID = DefaultADCClientID
	}

	if hostClient := p.hostClient(ctx); hostClient != nil {
		cacheKey := buildCacheKey(metadata.Flow, fingerprintHash(storedClientID), "")
		cached, cacheErr := cacheGetWithPrefix(ctx, hostClient, p.tokenCachePrefix(ctx), cacheKey)
		if cacheErr == nil && cached != nil && cached.IsValidFor(DefaultMinValidFor) {
			if cached.SessionID == "" || metadata.SessionID == "" || cached.SessionID == metadata.SessionID {
				return nil
			}
		}
	}

	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return err
	}

	var clientSecret string
	if storedClientID == DefaultADCClientID {
		clientSecret = DefaultADCClientSecret
	} else {
		clientSecret = cfg.ClientSecret
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", storedClientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	data.Set("refresh_token", refreshToken)

	resp, err := httpClient.PostForm(ctx, tokenEndpoint, data)
	if err != nil {
		return fmt.Errorf("token refresh failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errResp)
		if errResp.Error == "invalid_grant" {
			return fmt.Errorf("credentials expired or revoked (%s): %w", sanitizeControlChars(errResp.ErrorDescription), ErrTokenExpired)
		}
		return fmt.Errorf("token refresh failed: %s - %s", sanitizeControlChars(errResp.Error), sanitizeControlChars(errResp.ErrorDescription))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return fmt.Errorf("token refresh returned empty access_token")
	}
	return nil
}

// fetchUserinfoClaims fetches claims from Google's userinfo endpoint.
func (p *Plugin) fetchUserinfoClaims(ctx context.Context, accessToken string) (*auth.Claims, error) {
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return p.fetchUserinfoClaimsWithClient(ctx, httpClient, accessToken)
}

func (p *Plugin) fetchUserinfoClaimsWithClient(ctx context.Context, httpClient HTTPClient, accessToken string) (*auth.Claims, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("fetching user claims from Google userinfo API")

	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", accessToken),
	}

	resp, err := httpClient.Get(ctx, "https://openidconnect.googleapis.com/v1/userinfo", headers)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo API returned status %d", resp.StatusCode)
	}

	var userinfo struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&userinfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	username := ""
	if userinfo.Email != "" {
		if idx := strings.Index(userinfo.Email, "@"); idx > 0 {
			username = userinfo.Email[:idx]
		}
	}

	return &auth.Claims{
		Issuer:   "https://accounts.google.com",
		Subject:  userinfo.Subject,
		Email:    userinfo.Email,
		Name:     userinfo.Name,
		Username: username,
	}, nil
}
