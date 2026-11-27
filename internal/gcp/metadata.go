// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package gcp implements the GCP auth handler plugin for scafctl.
// This file implements the GCE metadata server token acquisition flow.
//
// SSRF EXCEPTION: The metadata service at 169.254.169.254 is a link-local
// address that would be blocked by httpc's SSRF protection. This file uses
// a dedicated net/http.Client (NOT httpc) scoped exclusively to the
// well-known metadata endpoint. This avoids polluting the shared HTTP client
// config with AllowPrivateIPs and matches how the GCP SDK itself handles
// metadata requests.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

const (
	// EnvGCEMetadataHost allows overriding the metadata server host for testing.
	EnvGCEMetadataHost = "GCE_METADATA_HOST"

	// defaultMetadataHost is the default GCE metadata server host.
	defaultMetadataHost = "metadata.google.internal"

	// metadataFlavorHeader is the required header for metadata server requests.
	metadataFlavorHeader = "Metadata-Flavor"

	// metadataFlavorValue is the required value for the Metadata-Flavor header.
	metadataFlavorValue = "Google"

	// metadataProbeTimeout is the timeout for probing the metadata server.
	metadataProbeTimeout = 2 * time.Second

	// metadataRequestTimeout is the timeout for metadata server token requests.
	metadataRequestTimeout = 10 * time.Second
)

// MetadataTokenResponse represents the token response from the metadata server.
type MetadataTokenResponse struct {
	AccessToken string `json:"access_token"` //nolint:gosec // G117: not a hardcoded credential, stores runtime token data
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// allowedMetadataHosts contains hosts that are permitted as metadata server
// overrides via GCE_METADATA_HOST. This prevents the env var from being used
// to redirect metadata requests to arbitrary endpoints (SSRF).
var allowedMetadataHosts = map[string]bool{
	"metadata.google.internal": true,
	"169.254.169.254":          true,
	"localhost":                true,
	"127.0.0.1":                true,
	"::1":                      true,
}

// getMetadataHost returns the metadata server host, respecting env var override.
// Only hosts in the allowlist are accepted; unknown overrides are ignored.
func getMetadataHost() string {
	if host := os.Getenv(EnvGCEMetadataHost); host != "" {
		// Strip port if present so the allowlist check works for host:port values.
		hostOnly := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			hostOnly = h
		}
		if allowedMetadataHosts[strings.ToLower(hostOnly)] {
			return host
		}
	}
	return defaultMetadataHost
}

// getMetadataTokenURL returns the full URL for the metadata server token endpoint.
func getMetadataTokenURL() string {
	return fmt.Sprintf("http://%s/computeMetadata/v1/instance/service-accounts/default/token", getMetadataHost())
}

// getMetadataEmailURL returns the full URL for the metadata server email endpoint.
func getMetadataEmailURL() string {
	return fmt.Sprintf("http://%s/computeMetadata/v1/instance/service-accounts/default/email", getMetadataHost())
}

// newMetadataHTTPClient creates a dedicated net/http.Client for metadata server
// requests only. This client is separate from the shared httpc-backed client
// because the metadata endpoint is a link-local address (169.254.169.254) that
// would be blocked by httpc's SSRF protection.
//
// The client is scoped to metadata-only operations and uses conservative timeouts.
func newMetadataHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
			DisableKeepAlives: true,
		},
	}
}

// isMetadataServerAvailable checks if the GCE metadata server is reachable.
// Uses a short timeout for probing.
func (p *Plugin) isMetadataServerAvailable(ctx context.Context) bool {
	client := newMetadataHTTPClient(metadataProbeTimeout)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getMetadataTokenURL(), nil)
	if err != nil {
		return false
	}
	req.Header.Set(metadataFlavorHeader, metadataFlavorValue)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}

// metadataLogin validates metadata server access by acquiring a token.
func (p *Plugin) metadataLogin(ctx context.Context, req sdkplugin.LoginRequest) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting metadata server login", "handler", HandlerName)

	// Acquire a token to validate access
	token, err := p.fetchMetadataToken(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("metadata server authentication failed: %w", err)
	}

	// Try to get the service account email
	claims := &auth.Claims{
		Issuer: "https://accounts.google.com",
	}

	email, emailErr := p.fetchMetadataEmail(ctx)
	if emailErr == nil && email != "" {
		claims.Subject = email
		claims.Email = email
	}

	// Store metadata with the effective scopes used for token acquisition
	effectiveScopes := req.Scopes
	if len(effectiveScopes) == 0 {
		effectiveScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
	}

	scopeStr := strings.Join(effectiveScopes, " ")
	cacheKey := buildCacheKey(auth.FlowMetadata, fingerprintHash(""), scopeStr)
	if _, err := p.storeMetadataAndSeedToken(ctx, claims, auth.FlowMetadata, effectiveScopes, cacheKey, token); err != nil {
		return nil, fmt.Errorf("failed to store metadata: %w", err)
	}

	lgr.V(1).Info("metadata server authentication successful", "email", email)

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// fetchMetadataToken acquires a token from the GCE metadata server using a
// dedicated net/http.Client (not httpc) to avoid SSRF protection blocking
// the link-local address.
func (p *Plugin) fetchMetadataToken(ctx context.Context, scope string) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	client := newMetadataHTTPClient(metadataRequestTimeout)

	tokenURL := getMetadataTokenURL()
	lgr.V(1).Info("requesting token from metadata server", "url", tokenURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating metadata request: %w", err)
	}
	req.Header.Set(metadataFlavorHeader, metadataFlavorValue)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metadata server request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata server not available: not running on Google Cloud? (status %d)", resp.StatusCode)
	}

	var tokenResp MetadataTokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse metadata token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("metadata server token response returned empty access_token")
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	lgr.V(1).Info("acquired metadata server token", "expiresIn", tokenResp.ExpiresIn)

	return &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scope,
		Flow:        auth.FlowMetadata,
	}, nil
}

// fetchMetadataEmail fetches the service account email from the metadata server.
func (p *Plugin) fetchMetadataEmail(ctx context.Context) (string, error) {
	client := newMetadataHTTPClient(metadataRequestTimeout)

	emailURL := getMetadataEmailURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, emailURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating metadata email request: %w", err)
	}
	req.Header.Set(metadataFlavorHeader, metadataFlavorValue)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata email request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata email request failed with status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", fmt.Errorf("reading metadata email response: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}

// getMetadataToken gets a token from metadata server, with caching.
func (p *Plugin) getMetadataToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	return p.getMetadataTokenWithMinValidFor(ctx, scope, forceRefresh, DefaultMinValidFor)
}

func (p *Plugin) getMetadataTokenWithMinValidFor(ctx context.Context, scope string, forceRefresh bool, minValidFor time.Duration) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	if minValidFor <= 0 {
		minValidFor = DefaultMinValidFor
	}

	prefix := p.tokenCachePrefix(ctx)
	sessionID := p.readFlowSessionID(ctx, auth.FlowMetadata, "")
	cacheKey := buildCacheKey(auth.FlowMetadata, fingerprintHash(""), scope)

	// Check cache first
	if !forceRefresh {
		if hostClient := p.hostClient(ctx); hostClient != nil {
			cached, err := cacheGetWithPrefix(ctx, hostClient, prefix, cacheKey)
			if err == nil && cached != nil && cached.IsValidFor(minValidFor) {
				if cached.SessionID == "" || sessionID == "" || cached.SessionID == sessionID {
					if cached.Flow == "" {
						cached.Flow = auth.FlowMetadata
					}
					if cached.SessionID == "" && sessionID != "" {
						cached.SessionID = sessionID
					}
					lgr.V(1).Info("using cached metadata token", "scope", scope)
					return cached, nil
				}
			}
		}
	}

	// Acquire new token
	token, err := p.fetchMetadataToken(ctx, scope)
	if err != nil {
		return nil, err
	}
	token.SessionID = sessionID

	// Cache it if the session is still current
	p.cacheTokenForSession(ctx, cacheKey, token)

	return token, nil
}
