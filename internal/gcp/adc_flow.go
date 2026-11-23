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
	"io"
	"net/http"
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

	// callbackShutdownTimeout bounds graceful draining of the localhost callback
	// HTTP response after a callback result is settled.
	callbackShutdownTimeout = 5 * time.Second

	// minUnprivilegedPort and maxTCPPort bound caller-requested callback ports
	// per sdkplugin.LoginRequest.CallbackPort.
	minUnprivilegedPort = 1024
	maxTCPPort          = 65535
)

type browserPreferenceKeyType struct{}

func withBrowserPreference(ctx context.Context, browser string) context.Context {
	return context.WithValue(ctx, browserPreferenceKeyType{}, browser)
}

func browserPreferenceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(browserPreferenceKeyType{}).(string)
	return v
}

// defaultBrowserOpener opens a URL in the user's preferred or default browser,
// logging fallback warnings when a configured browser preference or $BROWSER
// cannot be launched.
func defaultBrowserOpener(ctx context.Context, rawURL string) error {
	return oauth.OpenBrowserWithPreference(
		ctx,
		rawURL,
		browserPreferenceFromContext(ctx),
		oauth.WithWarningHandler(func(msg string) {
			logr.FromContextOrDiscard(ctx).V(0).Info(msg)
		}),
	)
}

func normalizeCallbackPort(port int) int {
	if port < minUnprivilegedPort || port > maxTCPPort {
		return 0
	}
	return port
}

// adcLogin performs the ADC browser OAuth flow (authorization code + PKCE).
func (p *Plugin) adcLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting ADC browser OAuth flow", "handler", HandlerName)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Use configured client ID, or fall back to Google's well-known ADC client credentials
	clientID := cfg.ClientID
	clientSecret := cfg.ClientSecret
	if clientID == "" {
		lgr.V(1).Info("no client ID configured, using Google's default ADC client credentials")
		clientID = DefaultADCClientID
		clientSecret = DefaultADCClientSecret
	}

	// Determine scopes
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = cfg.DefaultScopes
	}
	scopeStr := strings.Join(scopes, " ")

	// Generate PKCE code verifier and challenge
	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generating PKCE code verifier: %w", err)
	}
	codeChallenge := oauth.GenerateCodeChallenge(codeVerifier)

	// Generate random OAuth state for CSRF protection
	state, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generating OAuth state: %w", err)
	}

	// Start local callback server with deferred completion and Blueprint HTML pages
	callbackOpts := []oauth.CallbackOption{oauth.WithDeferredCompletion()}
	if pages := p.callbackPages(); pages != nil {
		callbackOpts = append(callbackOpts, oauth.WithCallbackPages(oauth.CallbackPages{
			SuccessHTML: pages.SuccessHTML,
			FailureHTML: pages.FailureHTML,
		}))
	}

	callbackPort := normalizeCallbackPort(req.CallbackPort)
	callbackServer, err := oauth.StartCallbackServer(ctx, callbackPort, state, callbackOpts...)
	if err != nil {
		return nil, fmt.Errorf("starting callback server: %w", err)
	}

	drained := false
	drainCallbackServer := func() {
		if drained {
			return
		}
		drained = true
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), callbackShutdownTimeout)
		defer shutdownCancel()
		_ = callbackServer.Shutdown(shutdownCtx)
	}
	defer drainCallbackServer()

	settleCallback := func(success bool) {
		callbackServer.Complete(success)
		drainCallbackServer()
	}

	redirectURI := callbackServer.RedirectURI

	// Build authorization URL
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&code_challenge=%s&code_challenge_method=S256&state=%s&access_type=offline&prompt=consent",
		authorizationEndpoint,
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scopeStr),
		url.QueryEscape(codeChallenge),
		url.QueryEscape(state),
	)

	// Open browser, forwarding any caller-requested browser preference
	lgr.V(1).Info("opening browser for authentication", "url", authURL, "browser", req.Browser)
	opener := p.browserOpener()
	browserOpenErr := opener(withBrowserPreference(ctx, req.Browser), authURL)
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
		timeout = DefaultTimeout
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var authCode string
	select {
	case result := <-callbackServer.ResultChan():
		if result.Err != nil {
			drainCallbackServer()
			return nil, result.Err
		}
		authCode = result.Code
		lgr.V(1).Info("received authorization code")
	case <-timer.C:
		settleCallback(false)
		return nil, fmt.Errorf("authentication timed out: no response received from browser: %w", ErrTimeout)
	case <-ctx.Done():
		settleCallback(false)
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

	resp, err := httpClient.PostForm(ctx, tokenEndpoint, data)
	if err != nil {
		settleCallback(false)
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errResp)
		settleCallback(false)
		if errResp.Error != "" {
			return nil, fmt.Errorf("token exchange failed: %s - %s",
				sanitizeControlChars(errResp.Error), sanitizeControlChars(errResp.ErrorDescription))
		}
		return nil, fmt.Errorf("token exchange failed with HTTP %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&tokenResp); err != nil {
		settleCallback(false)
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		settleCallback(false)
		return nil, fmt.Errorf("token exchange failed: token endpoint returned empty access_token")
	}

	// Validate and extract claims before mutating stored credentials so a
	// malformed ID token serves FailureHTML without leaving partial state.
	var claims *auth.Claims
	if tokenResp.IDToken != "" {
		claims, err = validateAndExtractIDTokenClaims(tokenResp.IDToken, clientID, time.Now())
		if err != nil {
			settleCallback(false)
			return nil, fmt.Errorf("failed to extract claims from ID token: %w", err)
		}
	} else {
		claims, err = p.fetchUserinfoClaimsWithClient(ctx, httpClient, tokenResp.AccessToken)
		if err != nil {
			if ctx.Err() != nil {
				settleCallback(false)
				if ctx.Err() == context.DeadlineExceeded {
					return nil, fmt.Errorf("authentication timed out: %w", ErrTimeout)
				}
				return nil, fmt.Errorf("authentication cancelled: %w", ErrUserCancelled)
			}
			claims = &auth.Claims{Issuer: "https://accounts.google.com"}
		}
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	// Use empty scope in key because mintToken/refresh never passes scope to
	// Google -- the token always covers all authorized scopes.
	initialCacheKey := buildCacheKey(auth.FlowInteractive, fingerprintHash(clientID), "")
	initialToken := &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scopeStr,
		Flow:        auth.FlowInteractive,
	}

	// Atomically commit credentials, clear stale cached tokens, and seed the new
	// access token under the profile write lock before settling SuccessHTML.
	_, err = p.storeCredentialsAndSeedToken(ctx, cfg, &tokenResp, auth.FlowInteractive, scopes, "", clientID, claims, initialCacheKey, initialToken)
	if err != nil {
		settleCallback(false)
		return nil, fmt.Errorf("failed to store credentials: %w", err)
	}

	settleCallback(true)

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

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	refreshToken, metadata, err := p.loadSessionCredentials(ctx)
	if err != nil {
		return nil, err
	}

	// For ADC flow, use the stored client ID as primary source, then fall
	// back to the default ADC client (not cfg) so a config change between
	// runs cannot break refresh.
	clientID := metadata.ClientID
	var clientSecret string
	switch clientID {
	case "":
		clientID = DefaultADCClientID
		clientSecret = DefaultADCClientSecret
	case DefaultADCClientID:
		clientSecret = DefaultADCClientSecret
	default:
		clientSecret = cfg.ClientSecret
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	data.Set("refresh_token", refreshToken)

	resp, err := httpClient.PostForm(ctx, tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errResp)

		bin := p.binaryName()
		if errResp.Error == "invalid_grant" {
			p.logoutIfRefreshRevisionMatches(ctx, metadata.SessionID, metadata.RefreshTokenID, metadata.RefreshTokenHash, refreshToken)
			return nil, fmt.Errorf(
				"GCP credentials have expired or been revoked (%s). "+
					"Run: %s auth login %s: %w",
				sanitizeControlChars(errResp.ErrorDescription), bin, HandlerName, ErrTokenExpired)
		}
		return nil, fmt.Errorf(
			"token refresh failed: %s - %s. Run: %s auth login %s to re-authenticate",
			sanitizeControlChars(errResp.Error), sanitizeControlChars(errResp.ErrorDescription), bin, HandlerName)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("token refresh failed: token endpoint returned empty access_token")
	}

	// Handle refresh token rotation unless a concurrent login or refresh replaced the revision
	if tokenResp.RefreshToken != "" && tokenResp.RefreshToken != refreshToken {
		lgr.V(1).Info("refresh token rotated, storing new token")
		if storeErr := p.storeRotatedCredentials(ctx, cfg, &tokenResp, metadata, refreshToken, clientID); storeErr != nil {
			lgr.V(1).Info("warning: failed to update refresh token", "error", storeErr)
		}
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	effectiveScope := scope
	if tokenResp.Scope != "" {
		effectiveScope = tokenResp.Scope
	}

	userFlow := metadata.Flow
	if userFlow == "" {
		userFlow = auth.FlowInteractive
	}

	return &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       effectiveScope,
		Flow:        userFlow,
		SessionID:   metadata.SessionID,
	}, nil
}

// getStoredRefreshToken gets a token using the stored refresh token, with caching.
func (p *Plugin) getStoredRefreshToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	return p.getStoredRefreshTokenWithMinValidFor(ctx, scope, forceRefresh, DefaultMinValidFor)
}

func (p *Plugin) getStoredRefreshTokenWithMinValidFor(ctx context.Context, scope string, forceRefresh bool, minValidFor time.Duration) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	if minValidFor <= 0 {
		minValidFor = DefaultMinValidFor
	}

	var userFlow auth.Flow
	var storedClientID string
	var sessionID string
	if metadata, err := p.loadMetadata(ctx); err == nil && metadata != nil {
		userFlow = metadata.Flow
		storedClientID = metadata.ClientID
		sessionID = metadata.SessionID
	}
	if userFlow == "" {
		userFlow = auth.FlowInteractive
	}
	if storedClientID == "" {
		storedClientID = DefaultADCClientID
	}

	fingerprint := fingerprintHash(storedClientID)
	prefix := p.tokenCachePrefix(ctx)

	// Check cache first. Use empty scope in key because mintToken/refresh never
	// passes scope to Google -- the token always covers all authorized scopes.
	if !forceRefresh {
		if hostClient := p.hostClient(ctx); hostClient != nil {
			cacheKey := buildCacheKey(userFlow, fingerprint, "")
			cached, cacheErr := cacheGetWithPrefix(ctx, hostClient, prefix, cacheKey)
			if cacheErr == nil && cached != nil && cached.IsValidFor(minValidFor) {
				if cached.SessionID == "" || sessionID == "" || cached.SessionID == sessionID {
					if cached.Flow == "" {
						cached.Flow = userFlow
					}
					lgr.V(1).Info("using cached token", "scope", scope)
					return cached, nil
				}
			}
		}
	}

	token, err := p.mintToken(ctx, scope)
	if err != nil {
		return nil, err
	}

	mintedClientID := storedClientID
	if metadata, metaErr := p.loadMetadata(ctx); metaErr == nil && metadata != nil && metadata.ClientID != "" {
		mintedClientID = metadata.ClientID
	}
	cacheKey := buildCacheKey(token.Flow, fingerprintHash(mintedClientID), "")
	p.cacheTokenForSession(ctx, cacheKey, token)

	return token, nil
}

// revokeRefreshToken revokes the stored refresh token with Google.
func (p *Plugin) revokeRefreshToken(ctx context.Context) error {
	refreshToken, err := p.loadRefreshToken(ctx)
	if err != nil || refreshToken == "" {
		return nil //nolint:nilerr // no refresh token to revoke
	}
	return p.revokeRefreshTokenValue(ctx, refreshToken)
}

func (p *Plugin) revokeRefreshTokenValue(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		cfg = p.baseConfig()
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("token revocation failed: %w", err)
	}

	data := url.Values{}
	data.Set("token", refreshToken)

	resp, err := httpClient.PostForm(ctx, revokeEndpoint, data)
	if err != nil {
		return fmt.Errorf("token revocation failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}
