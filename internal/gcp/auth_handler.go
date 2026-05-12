// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package gcp implements the GCP auth handler plugin for scafctl.
package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
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

	// SecretKeyRefreshToken is the secret key for storing the refresh token.
	SecretKeyRefreshToken = "scafctl.auth.gcp.refresh_token" //nolint:gosec // key name, not a credential

	// SecretKeyMetadata is the secret key for storing token metadata.
	SecretKeyMetadata = "scafctl.auth.gcp.metadata" //nolint:gosec // key name, not a credential

	// SecretKeyTokenPrefix is the prefix for cached access tokens.
	SecretKeyTokenPrefix = "scafctl.auth.gcp.token." //nolint:gosec // key prefix, not a credential

	// DefaultTimeout is the default timeout for browser OAuth flow.
	DefaultTimeout = 5 * time.Minute

	// DefaultMinValidFor is the minimum remaining validity for a cached token.
	DefaultMinValidFor = 5 * time.Minute
)

// BrowserOpenFunc is the signature for a function that opens a URL in the browser.
type BrowserOpenFunc func(ctx context.Context, url string) error

// Plugin implements the scafctl AuthHandlerPlugin interface.
type Plugin struct {
	cfg              sdkplugin.ProviderConfig
	config           *Config
	httpClient       HTTPClient
	clock            clock.Clock
	cachedHostClient *sdkplugin.HostServiceClient
	openBrowser      BrowserOpenFunc
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
			},
		},
	}, nil
}

// ConfigureAuthHandler stores host-side configuration and initializes the handler.
func (p *Plugin) ConfigureAuthHandler(ctx context.Context, handlerName string, cfg sdkplugin.ProviderConfig) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}

	p.cfg = cfg

	// Initialize config with defaults
	p.config = DefaultConfig()

	// Parse handler-specific settings if provided
	if raw, ok := cfg.Settings[HandlerName]; ok {
		if err := json.Unmarshal(raw, p.config); err != nil {
			return fmt.Errorf("failed to parse handler config: %w", err)
		}
	}

	if err := p.config.Validate(); err != nil {
		return err
	}

	// Initialize clock
	p.clock = clock.Real{}

	// Cache the host client for later use
	p.cachedHostClient = sdkplugin.HostClientFromContext(ctx)

	// Initialize HTTP client only if not already set (e.g. by tests)
	if p.httpClient == nil {
		httpLogger := logr.FromContextOrDiscard(ctx).V(5) // high verbosity for auth HTTP
		p.httpClient = NewDefaultHTTPClient(httpLogger)
	}

	// Initialize browser opener (can be overridden for testing)
	if p.openBrowser == nil {
		p.openBrowser = defaultBrowserOpener
	}

	return nil
}

// Login performs the authentication flow.
//
// Flow selection precedence:
//  1. WorkloadIdentity -- highest priority when env credentials exist
//  2. Metadata -- when running on GCE/GKE
//  3. ServicePrincipal -- when GOOGLE_APPLICATION_CREDENTIALS is set
//  4. DeviceCode -- when explicitly requested
//  5. GcloudADC -- when explicitly requested
//  6. Interactive (ADC browser OAuth) -- default
func (p *Plugin) Login(ctx context.Context, handlerName string, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	flow := req.Flow

	// Check if workload identity flow is requested or detected
	if flow == auth.FlowWorkloadIdentity || (flow == "" && HasWorkloadIdentityCredentials()) {
		return p.workloadIdentityLogin(ctx, req)
	}

	// Check if metadata server flow is requested or detected
	if flow == auth.FlowMetadata || (flow == "" && p.isMetadataServerAvailable(ctx)) {
		return p.metadataLogin(ctx, req)
	}

	// Check if service account flow is requested or detected
	if flow == auth.FlowServicePrincipal || (flow == "" && HasServiceAccountCredentials()) {
		return p.serviceAccountLogin(ctx, req)
	}

	// Check if device code flow is explicitly requested
	if flow == auth.FlowDeviceCode {
		return p.deviceCodeLogin(ctx, req, deviceCodeCb)
	}

	// Check if gcloud ADC flow is explicitly requested
	if flow == auth.FlowGcloudADC {
		return p.gcloudADCLogin(ctx, req)
	}

	// Default to ADC (native browser OAuth)
	return p.adcLogin(ctx, req, deviceCodeCb)
}

// Logout revokes the current session.
func (p *Plugin) Logout(ctx context.Context, handlerName string) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	return p.logoutInternal(ctx)
}

// logoutInternal clears stored credentials and cached tokens.
func (p *Plugin) logoutInternal(ctx context.Context) error {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("logging out", "handler", HandlerName)

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	// Revoke refresh token with Google (ADC flow only)
	if err := p.revokeRefreshToken(ctx); err != nil {
		lgr.V(1).Info("failed to revoke refresh token (may not exist)", "error", err)
	}

	// Clear all cached tokens
	cacheClear(ctx, lgr, hostClient)

	// Delete refresh token
	if err := hostClient.DeleteSecret(ctx, SecretKeyRefreshToken); err != nil {
		lgr.V(1).Info("failed to delete refresh token (may not exist)", "error", err)
	}

	// Delete metadata
	if err := hostClient.DeleteSecret(ctx, SecretKeyMetadata); err != nil {
		lgr.V(1).Info("failed to delete metadata (may not exist)", "error", err)
	}

	return nil
}

// GetStatus returns the current authentication status.
func (p *Plugin) GetStatus(ctx context.Context, handlerName string) (*auth.Status, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	// Check for workload identity credentials first (highest priority)
	if HasWorkloadIdentityCredentials() {
		return p.workloadIdentityStatus(ctx)
	}

	// Check for service account credentials
	if HasServiceAccountCredentials() {
		return p.serviceAccountStatus(ctx)
	}

	// Check for stored credentials (ADC flow)
	if !p.secretExists(ctx, SecretKeyMetadata) {
		// Check for gcloud ADC credentials as fallback
		if HasGcloudADCCredentials() {
			return &auth.Status{
				Authenticated: true,
				Claims: &auth.Claims{
					Issuer: "https://accounts.google.com",
					Name:   "gcloud ADC (application default credentials)",
				},
				IdentityType: auth.IdentityTypeUser,
			}, nil
		}

		// Check metadata server availability without requiring prior login
		if p.isMetadataServerAvailable(ctx) {
			return &auth.Status{
				Authenticated: true,
				Claims: &auth.Claims{
					Issuer: "https://accounts.google.com",
					Name:   "GCE/GKE metadata server",
				},
				IdentityType: auth.IdentityTypeServicePrincipal,
			}, nil
		}

		return &auth.Status{Authenticated: false}, nil
	}

	// Load metadata
	metadata, err := p.loadMetadata(ctx)
	if err != nil {
		return &auth.Status{Authenticated: false}, nil //nolint:nilerr // treat corrupted metadata as not authenticated
	}

	status := &auth.Status{
		Authenticated: true,
		Claims:        metadata.Claims,
		IdentityType:  auth.IdentityTypeUser,
		Scopes:        metadata.Scopes,
	}

	switch metadata.Flow { //nolint:exhaustive // only SA and WI need override
	case auth.FlowServicePrincipal:
		status.IdentityType = auth.IdentityTypeServicePrincipal
	case auth.FlowWorkloadIdentity:
		status.IdentityType = auth.IdentityTypeWorkloadIdentity
	}

	if !metadata.RefreshTokenExpiresAt.IsZero() {
		status.ExpiresAt = metadata.RefreshTokenExpiresAt
	}

	if metadata.ImpersonateServiceAccount != "" {
		status.ClientID = metadata.ImpersonateServiceAccount
	}

	// Check cached token validity without forcing a refresh to avoid side effects.
	if p.secretExists(ctx, SecretKeyRefreshToken) {
		scope := "https://www.googleapis.com/auth/cloud-platform"
		if len(metadata.Scopes) > 0 {
			scope = metadata.Scopes[0]
		}
		_, tokenErr := p.getStoredRefreshToken(ctx, scope, false)
		if tokenErr != nil {
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
	}

	return status, nil
}

// GetToken returns a valid access token, refreshing if necessary.
func (p *Plugin) GetToken(ctx context.Context, handlerName string, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	scope := req.Scope
	if scope == "" {
		return nil, fmt.Errorf("scope is required")
	}

	forceRefresh := req.ForceRefresh

	// Resolve the source token function based on priority
	token, err := p.resolveAndAcquireToken(ctx, scope, forceRefresh)
	if err != nil {
		return nil, err
	}

	return &sdkplugin.TokenResponse{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresAt:   token.ExpiresAt,
		Scope:       token.Scope,
	}, nil
}

// resolveAndAcquireToken determines the appropriate token source and acquires a token.
func (p *Plugin) resolveAndAcquireToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	// If impersonation is configured, get a source token first then impersonate
	if p.config.ImpersonateServiceAccount != "" {
		sourceToken, err := p.acquireSourceToken(ctx, scope, forceRefresh)
		if err != nil {
			return nil, fmt.Errorf("acquiring source token for impersonation: %w", err)
		}
		return p.getImpersonatedToken(ctx, sourceToken.AccessToken, scope, forceRefresh)
	}

	return p.acquireSourceToken(ctx, scope, forceRefresh)
}

// acquireSourceToken determines the appropriate credential source and acquires a token.
func (p *Plugin) acquireSourceToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	// Workload identity (highest priority)
	if HasWorkloadIdentityCredentials() {
		return p.getWorkloadIdentityToken(ctx, scope, forceRefresh)
	}

	// Metadata server -- check stored metadata or detect available metadata server
	metadata, err := p.loadMetadata(ctx)
	if err == nil && metadata != nil && metadata.Flow == auth.FlowMetadata {
		return p.getMetadataToken(ctx, scope, forceRefresh)
	}
	if p.isMetadataServerAvailable(ctx) {
		return p.getMetadataToken(ctx, scope, forceRefresh)
	}

	// Service account key
	if HasServiceAccountCredentials() {
		return p.getServiceAccountToken(ctx, scope, forceRefresh)
	}

	// Check for stored refresh token (ADC browser flow)
	if p.secretExists(ctx, SecretKeyRefreshToken) {
		return p.getStoredRefreshToken(ctx, scope, forceRefresh)
	}

	// Fallback to gcloud ADC
	if HasGcloudADCCredentials() {
		return p.getGcloudADCToken(ctx, scope, forceRefresh)
	}

	return nil, ErrNotAuthenticated
}

// ListCachedTokens returns information about cached tokens.
func (p *Plugin) ListCachedTokens(ctx context.Context, handlerName string) ([]*auth.CachedTokenInfo, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return nil, fmt.Errorf("host service not available")
	}

	var results []*auth.CachedTokenInfo

	// Refresh token (ADC browser flow)
	if p.secretExists(ctx, SecretKeyRefreshToken) {
		info := &auth.CachedTokenInfo{
			Handler:   HandlerName,
			TokenKind: "refresh",
		}
		if metadata, loadErr := p.loadMetadata(ctx); loadErr == nil && metadata != nil {
			info.ExpiresAt = metadata.RefreshTokenExpiresAt
			info.Flow = metadata.Flow
			info.SessionID = metadata.SessionID
		}
		if !info.ExpiresAt.IsZero() {
			info.IsExpired = time.Now().After(info.ExpiresAt)
		}
		results = append(results, info)
	}

	// Minted access tokens
	entries, listErr := cacheListEntries(ctx, hostClient)
	if listErr == nil {
		results = append(results, entries...)
	}

	return results, nil
}

// PurgeExpiredTokens removes expired tokens from the cache.
func (p *Plugin) PurgeExpiredTokens(ctx context.Context, handlerName string) (int, error) {
	if handlerName != HandlerName {
		return 0, fmt.Errorf("unknown handler: %s", handlerName)
	}

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return 0, fmt.Errorf("host service not available")
	}

	return cachePurgeExpired(ctx, hostClient)
}

// DetectAvailableFlows reports which flows have pre-existing environment credentials.
//
//nolint:revive // handlerName required by interface
func (p *Plugin) DetectAvailableFlows(ctx context.Context, handlerName string) ([]sdkplugin.FlowAvailability, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	var flows []sdkplugin.FlowAvailability

	// ADC: check for GOOGLE_APPLICATION_CREDENTIALS or default ADC file
	if HasGcloudADCCredentials() {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowGcloudADC,
			Available: true,
			Reason:    "gcloud application default credentials found",
		})
	}

	// Service account
	if HasServiceAccountCredentials() {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowServicePrincipal,
			Available: true,
			Reason:    "GOOGLE_APPLICATION_CREDENTIALS is set with service_account type",
		})
	}

	// Workload identity
	if HasWorkloadIdentityCredentials() {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowWorkloadIdentity,
			Available: true,
			Reason:    "GOOGLE_EXTERNAL_ACCOUNT is set",
		})
	}

	// Metadata server -- short timeout probe
	if p.isMetadataServerAvailable(ctx) {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowMetadata,
			Available: true,
			Reason:    "GCE/GKE metadata server is reachable",
		})
	}

	return flows, nil
}

// StopAuthHandler performs cleanup for the named handler.
//
//nolint:revive // all params required by interface
func (p *Plugin) StopAuthHandler(_ context.Context, _ string) error {
	return nil
}

// hostClient returns the HostServiceClient, preferring the one from context.
func (p *Plugin) hostClient(ctx context.Context) *sdkplugin.HostServiceClient {
	if hc := sdkplugin.HostClientFromContext(ctx); hc != nil {
		return hc
	}
	return p.cachedHostClient
}

// binaryName returns the binary name from config or a default.
func (p *Plugin) binaryName() string {
	if p.cfg.BinaryName != "" {
		return p.cfg.BinaryName
	}
	return "scafctl"
}

// fetchUserinfoClaims fetches claims from Google's userinfo endpoint.
func (p *Plugin) fetchUserinfoClaims(ctx context.Context, accessToken string) (*auth.Claims, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("fetching user claims from Google userinfo API")

	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", accessToken),
	}

	resp, err := p.httpClient.Get(ctx, "https://openidconnect.googleapis.com/v1/userinfo", headers)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("userinfo API returned status %d", resp.StatusCode)
	}

	var userinfo struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userinfo); err != nil {
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
