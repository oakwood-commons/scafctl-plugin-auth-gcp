// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package gcp implements the GCP auth handler plugin for scafctl.
// This file implements the ADC (Application Default Credentials) browser OAuth flow
// using authorization code + PKCE with a local redirect server.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	oauth "github.com/oakwood-commons/oauth-helpers"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

const (
	// Google OAuth 2.0 endpoints.
	authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenEndpoint         = "https://oauth2.googleapis.com/token" //nolint:gosec // G117: not a credential, it's an endpoint URL
	revokeEndpoint        = "https://oauth2.googleapis.com/revoke"
)

// defaultBrowserOpener opens a URL in the user's default browser.
func defaultBrowserOpener(ctx context.Context, url string) error {
	return oauth.OpenBrowser(ctx, url)
}

// adcLogin performs the ADC browser OAuth flow (authorization code + PKCE).
func (p *Plugin) adcLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting ADC browser OAuth flow", "handler", HandlerName)

	// Use configured client ID, or fall back to Google's well-known ADC client credentials
	clientID := p.config.ClientID
	clientSecret := p.config.ClientSecret
	if clientID == "" {
		lgr.V(1).Info("no client ID configured, using Google's default ADC client credentials")
		clientID = DefaultADCClientID
		clientSecret = DefaultADCClientSecret
	}

	// Determine scopes
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = p.config.DefaultScopes
	}
	scopeStr := strings.Join(scopes, " ")

	// Generate PKCE code verifier and challenge
	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generating PKCE code verifier: %w", err)
	}
	codeChallenge := oauth.GenerateCodeChallenge(codeVerifier)

	// Start local callback server for OAuth redirect
	callbackServer, err := oauth.StartCallbackServer(ctx, 0, "")
	if err != nil {
		return nil, fmt.Errorf("starting callback server: %w", err)
	}
	defer func() { _ = callbackServer.Close() }()
	redirectURI := callbackServer.RedirectURI

	// Build authorization URL
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&code_challenge=%s&code_challenge_method=S256&access_type=offline&prompt=consent",
		authorizationEndpoint,
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scopeStr),
		url.QueryEscape(codeChallenge),
	)

	// Open browser
	lgr.V(1).Info("opening browser for authentication", "url", authURL)
	browserOpenErr := p.openBrowser(ctx, authURL)
	if browserOpenErr != nil {
		lgr.V(0).Info("failed to open browser, please open this URL manually", "url", authURL)
	}
	// Always notify the CLI callback with the auth URL so the TUI can show
	// a "Re-open in browser" action.
	if deviceCodeCb != nil {
		deviceCodeCb(sdkplugin.DeviceCodePrompt{
			UserCode:        "",
			VerificationURI: authURL,
			Message:         "Open this URL in your browser to authenticate",
		})
	}

	// Wait for authorization code or timeout
	timeout := req.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var authCode string
	select {
	case result := <-callbackServer.ResultChan():
		if result.Err != nil {
			return nil, result.Err
		}
		authCode = result.Code
		lgr.V(1).Info("received authorization code")
	case <-timer.C:
		return nil, fmt.Errorf("authentication timed out: no response received from browser: %w", ErrTimeout)
	case <-ctx.Done():
		return nil, fmt.Errorf("authentication cancelled: %w", ErrUserCancelled)
	}

	// Exchange code for tokens
	data := url.Values{}
	data.Set("code", authCode)
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")
	data.Set("code_verifier", codeVerifier)

	resp, err := p.httpClient.PostForm(ctx, tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("token exchange failed: %s - %s", errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Store credentials
	if err := p.storeCredentials(ctx, &tokenResp, auth.FlowInteractive, scopes, "", clientID); err != nil {
		return nil, fmt.Errorf("failed to store credentials: %w", err)
	}

	// Cache the access token
	if tokenResp.AccessToken != "" {
		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		hostClient := p.hostClient(ctx)
		if hostClient != nil {
			cacheKey := buildCacheKey(auth.FlowInteractive, fingerprintHash(clientID), scopeStr)
			_ = cacheSet(ctx, hostClient, cacheKey, &auth.Token{
				AccessToken: tokenResp.AccessToken,
				TokenType:   tokenResp.TokenType,
				ExpiresAt:   expiresAt,
				Scope:       scopeStr,
				Flow:        auth.FlowInteractive,
			})
		}
	}

	// Extract claims
	claims, err := extractClaims(&tokenResp)
	if err != nil {
		// Try userinfo endpoint as fallback
		if tokenResp.AccessToken != "" {
			claims, err = p.fetchUserinfoClaims(ctx, tokenResp.AccessToken)
			if err != nil {
				claims = &auth.Claims{Issuer: "https://accounts.google.com"}
			}
		} else {
			claims = &auth.Claims{Issuer: "https://accounts.google.com"}
		}
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	lgr.V(1).Info("ADC browser OAuth flow completed successfully",
		"email", claims.Email,
		"expiresIn", tokenResp.ExpiresIn,
	)

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: expiresAt,
	}, nil
}

// mintToken creates a new access token using the stored refresh token.
func (p *Plugin) mintToken(ctx context.Context, scope string) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("minting access token", "scope", scope)

	refreshToken, err := p.loadRefreshToken(ctx)
	if err != nil {
		return nil, ErrNotAuthenticated
	}

	metadata, err := p.loadMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata: %w", err)
	}

	// For ADC flow, use the stored client ID as primary source, then fall
	// back to the default ADC client (not p.config) so a config change
	// between runs cannot break refresh.
	clientID := metadata.ClientID
	var clientSecret string
	switch clientID {
	case "":
		clientID = DefaultADCClientID
		clientSecret = DefaultADCClientSecret
	case DefaultADCClientID:
		clientSecret = DefaultADCClientSecret
	default:
		clientSecret = p.config.ClientSecret
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	data.Set("refresh_token", refreshToken)

	resp, err := p.httpClient.PostForm(ctx, tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)

		bin := p.binaryName()
		if errResp.Error == "invalid_grant" {
			_ = p.logoutInternal(ctx)
			return nil, fmt.Errorf(
				"GCP credentials have expired or been revoked (%s). "+
					"Run: %s auth login %s: %w",
				errResp.ErrorDescription, bin, HandlerName, ErrTokenExpired)
		}
		return nil, fmt.Errorf(
			"token refresh failed: %s - %s. Run: %s auth login %s to re-authenticate",
			errResp.Error, errResp.ErrorDescription, bin, HandlerName)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Handle refresh token rotation
	if tokenResp.RefreshToken != "" && tokenResp.RefreshToken != refreshToken {
		lgr.V(1).Info("refresh token rotated, storing new token")
		if storeErr := p.storeCredentials(ctx, &tokenResp, auth.FlowInteractive, metadata.Scopes, metadata.SessionID, clientID); storeErr != nil {
			lgr.V(1).Info("warning: failed to update refresh token", "error", storeErr)
		}
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	// Use the scope from the token response when available, since the refresh
	// request may not echo back the exact requested scope.
	effectiveScope := scope
	if tokenResp.Scope != "" {
		effectiveScope = tokenResp.Scope
	}

	return &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       effectiveScope,
		Flow:        auth.FlowInteractive,
		SessionID:   metadata.SessionID,
	}, nil
}

// getStoredRefreshToken gets a token using the stored refresh token, with caching.
func (p *Plugin) getStoredRefreshToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	// Determine the flow from stored metadata so we can partition the cache.
	var userFlow auth.Flow
	var storedClientID string
	if metadata, err := p.loadMetadata(ctx); err == nil && metadata != nil {
		userFlow = metadata.Flow
		storedClientID = metadata.ClientID
	}
	if storedClientID == "" {
		storedClientID = DefaultADCClientID
	}

	fingerprint := fingerprintHash(storedClientID)

	// Check cache first
	if !forceRefresh {
		hostClient := p.hostClient(ctx)
		if hostClient != nil {
			cacheKey := buildCacheKey(userFlow, fingerprint, scope)
			cached, cacheErr := cacheGet(ctx, hostClient, cacheKey)
			if cacheErr == nil && cached != nil && cached.IsValidFor(DefaultMinValidFor) {
				lgr.V(1).Info("using cached token", "scope", scope)
				return cached, nil
			}
		}
	}

	// Mint new token via refresh
	token, err := p.mintToken(ctx, scope)
	if err != nil {
		return nil, err
	}

	// Cache the token
	hostClient := p.hostClient(ctx)
	if hostClient != nil {
		cacheKey := buildCacheKey(userFlow, fingerprint, scope)
		if cacheSetErr := cacheSet(ctx, hostClient, cacheKey, token); cacheSetErr != nil {
			lgr.V(1).Info("failed to cache token", "error", cacheSetErr)
		}
	}

	return token, nil
}

// revokeRefreshToken revokes the stored refresh token with Google.
func (p *Plugin) revokeRefreshToken(ctx context.Context) error {
	refreshToken, err := p.loadRefreshToken(ctx)
	if err != nil {
		return nil // No refresh token to revoke
	}

	data := url.Values{}
	data.Set("token", refreshToken)

	resp, err := p.httpClient.PostForm(ctx, revokeEndpoint, data)
	if err != nil {
		return fmt.Errorf("token revocation failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}
