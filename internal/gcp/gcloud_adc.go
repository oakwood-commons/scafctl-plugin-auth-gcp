// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package gcp implements the GCP auth handler plugin for scafctl.
// This file implements the gcloud ADC (Application Default Credentials) fallback
// for users who have already run `gcloud auth application-default login`.
package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

const (
	// EnvCloudSDKConfig is the environment variable for custom gcloud config directory.
	EnvCloudSDKConfig = "CLOUDSDK_CONFIG"

	// defaultGcloudADCScope is the canonical scope used when caching gcloud ADC tokens
	// on the login path (tokenResp.Scope fallback) and for the status validation probe.
	// Using the same constant in both places maximises cache hit rate for the common case.
	defaultGcloudADCScope = "https://www.googleapis.com/auth/cloud-platform"
)

// ErrNoGcloudADCConfigured is returned when no gcloud ADC credentials are configured.
var ErrNoGcloudADCConfigured = errors.New("no gcloud ADC credentials configured")

// gcloudADCInvalidCredentialsError represents a definitive authentication failure (e.g.,
// expired or revoked credentials) as opposed to a transient network or server error.
type gcloudADCInvalidCredentialsError struct {
	msg string
}

func (e *gcloudADCInvalidCredentialsError) Error() string { return e.msg }

// formatGcloudTokenError converts a raw OAuth error response into a clear, actionable error.
func formatGcloudTokenError(errResp TokenErrorResponse, binaryName string) error {
	errCode := sanitizeControlChars(errResp.Error)
	errDesc := sanitizeControlChars(errResp.ErrorDescription)
	if errCode == "invalid_grant" {
		if strings.Contains(errDesc, "invalid_rapt") {
			return &gcloudADCInvalidCredentialsError{msg: fmt.Sprintf(
				"gcloud ADC credentials require re-authentication (invalid_rapt): "+
					"a security policy requires you to reauthenticate. "+
					"Run: gcloud auth application-default login OR %s auth login %s --flow interactive",
				binaryName, HandlerName,
			)}
		}
		return &gcloudADCInvalidCredentialsError{msg: fmt.Sprintf(
			"gcloud ADC credentials have expired or been revoked (%s). "+
				"Run: gcloud auth application-default login OR %s auth login %s --flow interactive",
			errDesc,
			binaryName, HandlerName,
		)}
	}
	return fmt.Errorf("gcloud ADC token refresh failed: %s - %s", errCode, errDesc)
}

// GcloudADCCredentials represents the structure of the gcloud ADC JSON file.
type GcloudADCCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` //nolint:gosec // This is a field name, not a credential
	RefreshToken string `json:"refresh_token"` //nolint:gosec // This is a field name, not a credential
	Type         string `json:"type"`
}

// getGcloudADCPath returns the path to the gcloud ADC credentials file.
func getGcloudADCPath() string {
	// Check GOOGLE_APPLICATION_CREDENTIALS first (when type is authorized_user)
	if path := os.Getenv(EnvGoogleApplicationCredentials); path != "" {
		// This is checked by LoadGcloudADCCredentials which validates type
		return path
	}

	// Check CLOUDSDK_CONFIG
	if dir := os.Getenv(EnvCloudSDKConfig); dir != "" {
		return filepath.Join(dir, "application_default_credentials.json")
	}

	// Platform-specific defaults
	switch runtime.GOOS {
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "gcloud", "application_default_credentials.json")
		}
	default:
		// Linux and macOS
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
		}
	}

	return ""
}

// LoadGcloudADCCredentials loads gcloud ADC credentials from the well-known location.
func LoadGcloudADCCredentials() (*GcloudADCCredentials, error) {
	path := getGcloudADCPath()
	if path == "" {
		return nil, ErrNoGcloudADCConfigured
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: path is from well-known gcloud config location, not user input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoGcloudADCConfigured
		}
		return nil, fmt.Errorf("reading gcloud ADC file: %w", err)
	}

	var creds GcloudADCCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("parsing gcloud ADC file: %w", err)
	}

	if creds.Type != "authorized_user" {
		return nil, ErrNoGcloudADCConfigured
	}

	if creds.RefreshToken == "" {
		return nil, ErrNoGcloudADCConfigured
	}

	return &creds, nil
}

// HasGcloudADCCredentials checks if gcloud ADC credentials exist.
func HasGcloudADCCredentials() bool {
	_, err := LoadGcloudADCCredentials()
	return err == nil
}

// gcloudADCLogin uses existing gcloud ADC credentials to authenticate.
func (p *Plugin) gcloudADCLogin(ctx context.Context, _ sdkplugin.LoginRequest) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("attempting gcloud ADC fallback login")

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	creds, err := LoadGcloudADCCredentials()
	if err != nil {
		if errors.Is(err, ErrNoGcloudADCConfigured) {
			return nil, fmt.Errorf("no gcloud ADC credentials found; run 'gcloud auth application-default login' or configure a client ID for %s", p.binaryName())
		}
		return nil, fmt.Errorf("loading gcloud ADC credentials: %w", err)
	}

	// Use gcloud's refresh token to get an access token
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", creds.ClientID)
	data.Set("client_secret", creds.ClientSecret)
	data.Set("refresh_token", creds.RefreshToken)

	resp, err := httpClient.PostForm(ctx, tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("gcloud ADC token refresh failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errResp)
		return nil, formatGcloudTokenError(errResp, p.binaryName())
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("gcloud ADC token refresh failed: token endpoint returned empty access_token")
	}

	// Extract claims from ID token or userinfo
	var claims *auth.Claims
	claims, err = extractClaims(&tokenResp)
	if err != nil || claims.Email == "" {
		claims, err = p.fetchUserinfoClaimsWithClient(ctx, httpClient, tokenResp.AccessToken)
		if err != nil {
			if ctx.Err() != nil {
				if ctx.Err() == context.DeadlineExceeded {
					return nil, fmt.Errorf("authentication timed out: %w", ErrTimeout)
				}
				return nil, fmt.Errorf("authentication cancelled: %w", ErrUserCancelled)
			}
			claims = &auth.Claims{Issuer: "https://accounts.google.com"}
		}
	}

	// Compute effective scopes from token response for metadata storage
	scopeStr := tokenResp.Scope
	if scopeStr == "" {
		scopeStr = defaultGcloudADCScope
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	cacheKey := buildCacheKey(auth.FlowGcloudADC, fingerprintHash(creds.ClientID), scopeStr)
	initialToken := &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scopeStr,
		Flow:        auth.FlowGcloudADC,
	}

	// Store metadata (but NOT the refresh token -- we leave that in gcloud's file)
	// and atomically seed the cached access token under ctx's profile.
	if _, err := p.storeMetadataAndSeedToken(ctx, claims, auth.FlowGcloudADC, strings.Fields(scopeStr), cacheKey, initialToken); err != nil {
		lgr.V(1).Info("warning: failed to store metadata", "error", err)
	}

	lgr.V(1).Info("gcloud ADC fallback login successful", "email", claims.Email)

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: expiresAt,
	}, nil
}

// getGcloudADCToken refreshes a token using gcloud ADC credentials, with caching.
func (p *Plugin) getGcloudADCToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	return p.getGcloudADCTokenWithMinValidFor(ctx, scope, forceRefresh, DefaultMinValidFor)
}

func (p *Plugin) getGcloudADCTokenWithMinValidFor(ctx context.Context, scope string, forceRefresh bool, minValidFor time.Duration) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	if minValidFor <= 0 {
		minValidFor = DefaultMinValidFor
	}

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	creds, err := LoadGcloudADCCredentials()
	if err != nil {
		return nil, ErrNotAuthenticated
	}

	fingerprint := fingerprintHash(creds.ClientID)
	prefix := p.tokenCachePrefix(ctx)
	sessionID := p.readFlowSessionID(ctx, auth.FlowGcloudADC)
	cacheKey := buildCacheKey(auth.FlowGcloudADC, fingerprint, scope)

	// Check cache first
	if !forceRefresh {
		if hostClient := p.hostClient(ctx); hostClient != nil {
			cached, cacheErr := cacheGetWithPrefix(ctx, hostClient, prefix, cacheKey)
			if cacheErr == nil && cached != nil && cached.IsValidFor(minValidFor) {
				if cached.SessionID == "" || sessionID == "" || cached.SessionID == sessionID {
					lgr.V(1).Info("using cached gcloud ADC token", "scope", scope)
					return cached, nil
				}
			}
		}
	}

	// Refresh token using gcloud's credentials
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", creds.ClientID)
	data.Set("client_secret", creds.ClientSecret)
	data.Set("refresh_token", creds.RefreshToken)

	resp, err := httpClient.PostForm(ctx, tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("gcloud ADC token refresh failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errResp)
		return nil, formatGcloudTokenError(errResp, p.binaryName())
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("gcloud ADC token refresh failed: token endpoint returned empty access_token")
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	token := &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scope,
		Flow:        auth.FlowGcloudADC,
		SessionID:   sessionID,
	}

	binaryName := p.binaryName()
	lgr.V(1).Info("acquired token via gcloud ADC fallback",
		"hint", fmt.Sprintf("to use %s-managed credentials run: %s auth login %s", binaryName, binaryName, HandlerName))

	p.cacheTokenForSession(ctx, cacheKey, token)

	return token, nil
}

// validateGcloudADCCredentials checks whether gcloud ADC credentials can produce a valid token.
// It reads from the token cache when available (no side effect), and probes the token endpoint
// on a cache miss without persisting the result -- making it safe to call from GetStatus.
func (p *Plugin) validateGcloudADCCredentials(ctx context.Context) error {
	creds, err := LoadGcloudADCCredentials()
	if err != nil {
		if errors.Is(err, ErrNoGcloudADCConfigured) {
			return ErrNotAuthenticated
		}
		return fmt.Errorf("loading gcloud ADC credentials: %w", err)
	}

	// Check cache first (read-only, no side effect).
	if hostClient := p.hostClient(ctx); hostClient != nil {
		cacheKey := buildCacheKey(auth.FlowGcloudADC, fingerprintHash(creds.ClientID), defaultGcloudADCScope)
		cached, cacheErr := cacheGetWithPrefix(ctx, hostClient, p.tokenCachePrefix(ctx), cacheKey)
		if cacheErr == nil && cached != nil && cached.IsValidFor(DefaultMinValidFor) {
			return nil
		}
	}

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return err
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return err
	}

	// No valid cached token -- probe the token endpoint without persisting the result.
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", creds.ClientID)
	data.Set("client_secret", creds.ClientSecret)
	data.Set("refresh_token", creds.RefreshToken)

	resp, err := httpClient.PostForm(ctx, tokenEndpoint, data)
	if err != nil {
		return fmt.Errorf("gcloud ADC token refresh failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if decodeErr := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errResp); decodeErr != nil || errResp.Error == "" {
			return fmt.Errorf("gcloud ADC token refresh failed: HTTP %d %s", resp.StatusCode, sanitizeControlChars(resp.Status))
		}
		return formatGcloudTokenError(errResp, p.binaryName())
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&tokenResp); err != nil {
		return fmt.Errorf("gcloud ADC validation: unexpected token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return fmt.Errorf("gcloud ADC validation: token endpoint returned 200 but access_token is empty")
	}
	return nil
}
