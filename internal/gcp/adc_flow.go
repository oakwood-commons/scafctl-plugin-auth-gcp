// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package gcp implements the GCP auth handler plugin for scafctl.
// This file implements the ADC (Application Default Credentials) browser OAuth flow
// using authorization code + PKCE with a local redirect server.
package gcp

import (
	"context"
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

	// Start local callback server on a dedicated background context so callback
	// settlement is serialized through callbackCommitGate rather than racing
	// oauth-helpers' internal context.AfterFunc during credential commit.
	callbackOpts := []oauth.CallbackOption{oauth.WithDeferredCompletion()}
	if pages := p.callbackPages(); pages != nil {
		callbackOpts = append(callbackOpts, oauth.WithCallbackPages(oauth.CallbackPages{
			SuccessHTML: pages.SuccessHTML,
			FailureHTML: pages.FailureHTML,
		}))
	}

	cbCtx, cancelCB := context.WithCancel(context.Background())
	defer cancelCB()

	callbackPort := normalizeCallbackPort(req.CallbackPort)
	callbackServer, err := oauth.StartCallbackServer(cbCtx, callbackPort, state, callbackOpts...)
	if err != nil {
		return nil, fmt.Errorf("starting callback server: %w", err)
	}

	gate := &callbackCommitGate{server: callbackServer}

	drained := false
	drainCallbackServer := func() {
		if drained {
			return
		}
		drained = true
		gate.settleFailure()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), callbackShutdownTimeout)
		defer shutdownCancel()
		_ = callbackServer.Shutdown(shutdownCtx)
	}
	defer drainCallbackServer()

	stopCancelWatch := context.AfterFunc(ctx, gate.settleFailure)
	defer stopCancelWatch()

	settleCallbackFailure := func() {
		gate.settleFailure()
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
		settleCallbackFailure()
		return nil, fmt.Errorf("authentication timed out: no response received from browser: %w", ErrTimeout)
	case <-ctx.Done():
		settleCallbackFailure()
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
		settleCallbackFailure()
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errResp)
		settleCallbackFailure()
		if errResp.Error != "" {
			return nil, fmt.Errorf("token exchange failed: %s - %s",
				sanitizeControlChars(errResp.Error), sanitizeControlChars(errResp.ErrorDescription))
		}
		return nil, fmt.Errorf("token exchange failed with HTTP %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&tokenResp); err != nil {
		settleCallbackFailure()
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		settleCallbackFailure()
		return nil, fmt.Errorf("token exchange failed: token endpoint returned empty access_token")
	}

	// Validate and extract claims before mutating stored credentials so an
	// invalid ID token or failed userinfo lookup serves FailureHTML without
	// overwriting any previously authenticated session.
	var claims *auth.Claims
	if tokenResp.IDToken != "" {
		claims, err = validateAndExtractIDTokenClaims(tokenResp.IDToken, clientID, time.Now())
		if err != nil {
			settleCallbackFailure()
			return nil, fmt.Errorf("failed to extract claims from ID token: %w", err)
		}
	} else {
		claims, err = p.fetchUserinfoClaimsWithClient(ctx, httpClient, tokenResp.AccessToken)
		if err != nil {
			settleCallbackFailure()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("authentication timed out: %w", ErrTimeout)
			}
			if ctx.Err() != nil {
				return nil, fmt.Errorf("authentication cancelled: %w", ErrUserCancelled)
			}
			return nil, fmt.Errorf("failed to fetch userinfo claims: %w", err)
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

	// Atomically stage credentials and access-token seed under the profile write
	// lock and coordinate callback settlement via gate.trySettleSuccess: if ctx
	// cancellation won at any point (including during the detached legacy-mirror
	// write), staged writes are rolled back to the prior session snapshot and
	// FailureHTML matches the returned cancellation error.
	_, err = p.storeCredentialsAndSeedTokenWithHook(ctx, cfg, &tokenResp, auth.FlowInteractive, scopes, "", clientID, claims, initialCacheKey, initialToken, gate.trySettleSuccess)
	if err != nil {
		settleCallbackFailure()
		if errors.Is(err, ErrTimeout) || errors.Is(err, ErrUserCancelled) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to store credentials: %w", err)
	}

	drainCallbackServer()

	lgr.V(1).Info("ADC browser OAuth flow completed successfully",
		"email", claims.Email,
		"expiresIn", tokenResp.ExpiresIn,
	)

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: expiresAt,
	}, nil
}

// callbackCommitGate linearizes cancellation against localhost OAuth callback
// completion so browser HTTP status (200 SuccessHTML vs 503 FailureHTML) always
// matches whether the login session committed or rolled back.
type callbackCommitGate struct {
	mu      sync.Mutex
	server  *oauth.CallbackServer
	settled bool
}

func (g *callbackCommitGate) settleFailure() {
	g.mu.Lock()
	if !g.settled {
		g.settled = true
		g.server.Complete(false)
	}
	g.mu.Unlock()
}

func (g *callbackCommitGate) trySettleSuccess(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.settled || ctx.Err() != nil {
		if !g.settled {
			g.settled = true
			g.server.Complete(false)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("authentication timed out: %w", ErrTimeout)
		}
		return fmt.Errorf("authentication cancelled: %w", ErrUserCancelled)
	}
	g.settled = true
	g.server.Complete(true)
	return nil
}

// mintToken creates a new access token using the stored refresh token,
// serializing refresh-grant consumption for ctx's profile without holding
// profileLock across external HTTP calls.
func (p *Plugin) mintToken(ctx context.Context, scope string) (*auth.Token, error) {
	unlock, err := p.acquireRefreshLock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	token, _, err := p.mintTokenLocked(ctx, scope)
	return token, err
}

// mintTokenLocked performs a single refresh-token exchange while the caller
// holds acquireRefreshLock(ctx).
func (p *Plugin) mintTokenLocked(ctx context.Context, scope string) (*auth.Token, string, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("minting access token", "scope", scope)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, "", err
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, "", err
	}

	refreshToken, metadata, err := p.loadSessionCredentials(ctx)
	if err != nil {
		return nil, "", err
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
		return nil, "", fmt.Errorf("token refresh failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errResp)

		bin := p.binaryName()
		if errResp.Error == "invalid_grant" {
			p.logoutIfRefreshRevisionMatches(ctx, metadata.SessionID, metadata.RefreshTokenID, metadata.RefreshTokenHash, refreshToken)
			return nil, "", fmt.Errorf(
				"GCP credentials have expired or been revoked (%s). "+
					"Run: %s auth login %s: %w",
				sanitizeControlChars(errResp.ErrorDescription), bin, HandlerName, ErrTokenExpired)
		}
		return nil, "", fmt.Errorf(
			"token refresh failed: %s - %s. Run: %s auth login %s to re-authenticate",
			sanitizeControlChars(errResp.Error), sanitizeControlChars(errResp.ErrorDescription), bin, HandlerName)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&tokenResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, "", fmt.Errorf("token refresh failed: token endpoint returned empty access_token")
	}

	// Persist rotated refresh tokens before returning or caching the access token
	// so callers detect storage failures before relying on a superseded grant.
	if tokenResp.RefreshToken != "" && tokenResp.RefreshToken != refreshToken {
		lgr.V(1).Info("refresh token rotated, storing new token")
		if storeErr := p.storeRotatedCredentials(ctx, cfg, &tokenResp, metadata, refreshToken, clientID); storeErr != nil {
			return nil, "", fmt.Errorf("persisting rotated refresh token: %w", storeErr)
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
	}, clientID, nil
}

// getStoredRefreshToken gets a token using the stored refresh token, with caching.
func (p *Plugin) getStoredRefreshToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	return p.getStoredRefreshTokenWithMinValidFor(ctx, scope, forceRefresh, DefaultMinValidFor)
}

func (p *Plugin) lookupCachedRefreshFlowToken(ctx context.Context, minValidFor time.Duration) (*auth.Token, string) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return nil, ""
	}

	mu := p.profileLock(ctx)
	mu.RLock()
	defer mu.RUnlock()

	metadata, _, hasRefresh, err := p.inspectStoredMetadataAndRefreshUnlocked(ctx)
	if err != nil || metadata == nil || !isRefreshTokenFlow(metadata.Flow) {
		return nil, ""
	}

	userFlow := metadata.Flow
	if userFlow == "" {
		userFlow = auth.FlowInteractive
	}
	storedClientID := metadata.ClientID
	if storedClientID == "" {
		storedClientID = DefaultADCClientID
	}
	sessionID := metadata.SessionID

	// Use empty scope in key because mintToken/refresh never passes scope to
	// Google -- the token always covers all authorized scopes.
	cacheKey := buildCacheKey(userFlow, fingerprintHash(storedClientID), "")
	cached, cacheErr := cacheGetWithPrefix(ctx, hostClient, p.tokenCachePrefix(ctx), cacheKey)
	if cacheErr != nil || cached == nil || !cached.IsValidFor(minValidFor) {
		return nil, ""
	}
	if !hasRefresh && sessionID != "" {
		if cached.SessionID != sessionID {
			return nil, ""
		}
	} else if cached.SessionID != "" && sessionID != "" && cached.SessionID != sessionID {
		return nil, ""
	}
	if cached.Flow == "" {
		cached.Flow = userFlow
	}
	if cached.SessionID == "" && sessionID != "" {
		cached.SessionID = sessionID
	}
	return cached, storedClientID
}

func (p *Plugin) getStoredRefreshTokenWithMinValidFor(ctx context.Context, scope string, forceRefresh bool, minValidFor time.Duration) (*auth.Token, error) {
	token, _, err := p.getStoredRefreshTokenWithIdentity(ctx, scope, forceRefresh, minValidFor)
	return token, err
}

func (p *Plugin) getStoredRefreshTokenWithIdentity(ctx context.Context, scope string, forceRefresh bool, minValidFor time.Duration) (*auth.Token, string, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	if minValidFor <= 0 {
		minValidFor = DefaultMinValidFor
	}

	if !forceRefresh {
		if cached, cachedClientID := p.lookupCachedRefreshFlowToken(ctx, minValidFor); cached != nil {
			lgr.V(1).Info("using cached token", "scope", scope)
			return cached, cachedClientID, nil
		}
	}

	unlock, err := p.acquireRefreshLock(ctx)
	if err != nil {
		return nil, "", err
	}
	defer unlock()

	// Re-check cache after acquiring refresh lock so concurrent callers coalesce
	// onto the access token just minted by the preceding holder.
	if !forceRefresh {
		if cached, cachedClientID := p.lookupCachedRefreshFlowToken(ctx, minValidFor); cached != nil {
			lgr.V(1).Info("using cached token", "scope", scope)
			return cached, cachedClientID, nil
		}
	}

	token, mintedClientID, err := p.mintTokenLocked(ctx, scope)
	if err != nil {
		return nil, "", err
	}

	cacheKey := buildCacheKey(token.Flow, fingerprintHash(mintedClientID), "")
	p.cacheTokenForSession(ctx, cacheKey, token)

	return token, mintedClientID, nil
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
