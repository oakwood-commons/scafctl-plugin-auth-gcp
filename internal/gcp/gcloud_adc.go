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
)

// ErrNoGcloudADCConfigured is returned when no gcloud ADC credentials are configured.
var ErrNoGcloudADCConfigured = errors.New("no gcloud ADC credentials configured")

// formatGcloudTokenError converts a raw OAuth error response into a clear, actionable error.
func formatGcloudTokenError(errResp TokenErrorResponse, binaryName string) error {
	if errResp.Error == "invalid_grant" {
		if strings.Contains(errResp.ErrorDescription, "invalid_rapt") {
			return fmt.Errorf(
				"gcloud ADC credentials require re-authentication (invalid_rapt): "+
					"a security policy requires you to reauthenticate. "+
					"Run: %s auth login %s",
				binaryName, HandlerName,
			)
		}
		return fmt.Errorf(
			"gcloud ADC credentials have expired or been revoked (%s). "+
				"Run: %s auth login %s",
			errResp.ErrorDescription,
			binaryName, HandlerName,
		)
	}
	return fmt.Errorf("gcloud ADC token refresh failed: %s - %s", errResp.Error, errResp.ErrorDescription)
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

	resp, err := p.httpClient.PostForm(ctx, tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("gcloud ADC token refresh failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, formatGcloudTokenError(errResp, p.binaryName())
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Extract claims from ID token or userinfo
	var claims *auth.Claims
	claims, err = extractClaims(&tokenResp)
	if err != nil || claims.Email == "" {
		if tokenResp.AccessToken != "" {
			claims, err = p.fetchUserinfoClaims(ctx, tokenResp.AccessToken)
			if err != nil {
				claims = &auth.Claims{Issuer: "https://accounts.google.com"}
			}
		}
	}

	// Compute effective scopes from token response for metadata storage
	scopeStr := tokenResp.Scope
	if scopeStr == "" {
		scopeStr = "https://www.googleapis.com/auth/cloud-platform"
	}

	// Store metadata (but NOT the refresh token -- we leave that in gcloud's file)
	if err := p.storeMetadataOnly(ctx, claims, auth.FlowGcloudADC, strings.Fields(scopeStr)); err != nil {
		lgr.V(1).Info("warning: failed to store metadata", "error", err)
	}

	// Cache the access token
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	hostClient := p.hostClient(ctx)
	if hostClient != nil {
		cacheKey := buildCacheKey(auth.FlowGcloudADC, fingerprintHash(creds.ClientID), scopeStr)
		_ = cacheSet(ctx, hostClient, cacheKey, &auth.Token{
			AccessToken: tokenResp.AccessToken,
			TokenType:   tokenResp.TokenType,
			ExpiresAt:   expiresAt,
			Scope:       scopeStr,
			Flow:        auth.FlowGcloudADC,
		})
	}

	lgr.V(1).Info("gcloud ADC fallback login successful", "email", claims.Email)

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: expiresAt,
	}, nil
}

// getGcloudADCToken refreshes a token using gcloud ADC credentials, with caching.
func (p *Plugin) getGcloudADCToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	creds, err := LoadGcloudADCCredentials()
	if err != nil {
		return nil, ErrNotAuthenticated
	}

	fingerprint := fingerprintHash(creds.ClientID)

	// Check cache first
	if !forceRefresh {
		hostClient := p.hostClient(ctx)
		if hostClient != nil {
			cacheKey := buildCacheKey(auth.FlowGcloudADC, fingerprint, scope)
			cached, cacheErr := cacheGet(ctx, hostClient, cacheKey)
			if cacheErr == nil && cached != nil && cached.IsValidFor(DefaultMinValidFor) {
				lgr.V(1).Info("using cached gcloud ADC token", "scope", scope)
				return cached, nil
			}
		}
	}

	// Refresh token using gcloud's credentials
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", creds.ClientID)
	data.Set("client_secret", creds.ClientSecret)
	data.Set("refresh_token", creds.RefreshToken)

	resp, err := p.httpClient.PostForm(ctx, tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("gcloud ADC token refresh failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, formatGcloudTokenError(errResp, p.binaryName())
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	token := &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scope,
		Flow:        auth.FlowGcloudADC,
	}

	binaryName := p.binaryName()
	lgr.V(1).Info("acquired token via gcloud ADC fallback",
		"hint", fmt.Sprintf("to use %s-managed credentials run: %s auth login %s", binaryName, binaryName, HandlerName))

	hostClient := p.hostClient(ctx)
	if hostClient != nil {
		cacheKey := buildCacheKey(auth.FlowGcloudADC, fingerprint, scope)
		if cacheSetErr := cacheSet(ctx, hostClient, cacheKey, token); cacheSetErr != nil {
			lgr.V(1).Info("failed to cache gcloud ADC token", "error", cacheSetErr)
		}
	}

	return token, nil
}
