// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

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
	"time"

	"github.com/go-logr/logr"
	oauth "github.com/oakwood-commons/oauth-helpers"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

const (
	// deviceCodeEndpoint is the Google OAuth 2.0 device authorization endpoint.
	deviceCodeEndpoint = "https://oauth2.googleapis.com/device/code"

	// defaultDeviceCodePollInterval is the minimum polling interval for device code flow.
	defaultDeviceCodePollInterval = 5 * time.Second

	// slowDownIncrement is the interval increase when the server returns "slow_down".
	slowDownIncrement = 5 * time.Second
)

// DeviceCodeResponse represents the response from Google's device authorization endpoint.
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// deviceCodeLogin performs the OAuth 2.0 device code authentication flow.
func (p *Plugin) deviceCodeLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting GCP device code authentication flow", "handler", HandlerName)

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

	// Determine timeout
	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Step 1: Request device code from Google
	isDefaultClient := clientID == DefaultADCClientID
	deviceCode, err := p.requestGCPDeviceCode(ctx, clientID, scopes)
	if err != nil {
		if isDefaultClient {
			return nil, fmt.Errorf("device code request failed with default ADC client (configure clientId and clientSecret for device code support): %w", err)
		}
		return nil, fmt.Errorf("device code request failed: %w", err)
	}

	safeUserCode := sanitizeControlChars(deviceCode.UserCode)
	safeVerificationURL := sanitizeControlChars(deviceCode.VerificationURL)

	lgr.V(1).Info("device code obtained",
		"userCode", safeUserCode,
		"verificationURL", safeVerificationURL,
	)

	// Step 2: Notify callback with device code info for CLI display
	if deviceCodeCb != nil {
		deviceCodeCb(sdkplugin.DeviceCodePrompt{
			UserCode:        safeUserCode,
			VerificationURI: safeVerificationURL,
			Message:         "Enter this code to authenticate with Google Cloud",
		})
	}

	// Step 3: Poll for token
	tokenResp, err := p.pollGCPDeviceToken(ctx, deviceCode, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("device code polling failed: %w", err)
	}

	// Step 4: Validate and extract claims before mutating stored credentials
	var claims *auth.Claims
	if tokenResp.IDToken != "" {
		claims, err = validateAndExtractIDTokenClaims(tokenResp.IDToken, clientID, time.Now())
		if err != nil {
			return nil, fmt.Errorf("failed to extract claims from ID token: %w", err)
		}
	} else if tokenResp.AccessToken != "" {
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
	} else {
		claims = &auth.Claims{Issuer: "https://accounts.google.com"}
	}

	// Step 5: Atomically commit credentials and seed cached access token
	scopeStr := strings.Join(scopes, " ")
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	var initialCacheKey string
	var initialToken *auth.Token
	if tokenResp.AccessToken != "" {
		initialCacheKey = buildCacheKey(auth.FlowDeviceCode, fingerprintHash(clientID), "")
		initialToken = &auth.Token{
			AccessToken: tokenResp.AccessToken,
			TokenType:   tokenResp.TokenType,
			ExpiresAt:   expiresAt,
			Scope:       scopeStr,
			Flow:        auth.FlowDeviceCode,
		}
	}

	_, err = p.storeCredentialsAndSeedToken(ctx, cfg, tokenResp, auth.FlowDeviceCode, scopes, "", clientID, claims, initialCacheKey, initialToken)
	if err != nil {
		return nil, fmt.Errorf("failed to store credentials: %w", err)
	}

	lgr.V(1).Info("GCP device code flow completed successfully",
		"email", claims.Email,
		"expiresIn", tokenResp.ExpiresIn,
	)

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: expiresAt,
	}, nil
}

// requestGCPDeviceCode requests a device code from Google's device authorization endpoint.
func (p *Plugin) requestGCPDeviceCode(ctx context.Context, clientID string, scopes []string) (*DeviceCodeResponse, error) {
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", strings.Join(scopes, " "))

	resp, err := httpClient.PostForm(ctx, deviceCodeEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errResp)
		return nil, fmt.Errorf("device code request failed (%d): %s - %s",
			resp.StatusCode, sanitizeControlChars(errResp.Error), sanitizeControlChars(errResp.ErrorDescription))
	}

	var deviceCode DeviceCodeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&deviceCode); err != nil {
		return nil, fmt.Errorf("failed to parse device code response: %w", err)
	}

	return &deviceCode, nil
}

// pollGCPDeviceToken polls Google's token endpoint until the user completes
// authentication or the device code expires.
func (p *Plugin) pollGCPDeviceToken(ctx context.Context, deviceCode *DeviceCodeResponse, clientID, clientSecret string) (*TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	pollCfg := oauth.DevicePollConfig{
		Interval:             time.Duration(deviceCode.Interval) * time.Second,
		MinInterval:          defaultDeviceCodePollInterval,
		SlowDownIncrement:    slowDownIncrement,
		RetryTransientErrors: true,
		Sleep:                p.getClock().Sleep,
		OnSlowDown: func(newInterval time.Duration) {
			lgr.V(1).Info("slow_down received, increasing poll interval", "newInterval", newInterval)
		},
		OnTransientError: func(transientErr error) {
			lgr.V(1).Info("transient network error during device code poll, continuing", "error", transientErr)
		},
	}

	tokenResp, err := oauth.PollDeviceToken(ctx, pollCfg, func(pollCtx context.Context) (*TokenResponse, *oauth.DevicePollError, error) {
		data := url.Values{}
		data.Set("client_id", clientID)
		if clientSecret != "" {
			data.Set("client_secret", clientSecret)
		}
		data.Set("device_code", deviceCode.DeviceCode)
		data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

		resp, reqErr := httpClient.PostForm(pollCtx, tokenEndpoint, data)
		if reqErr != nil {
			return nil, nil, reqErr
		}

		var body struct {
			TokenResponse
			TokenErrorResponse
		}
		decodeErr := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&body)
		_ = resp.Body.Close()
		if decodeErr != nil {
			return nil, &oauth.DevicePollError{
				Cause: fmt.Errorf("failed to parse token response: %w", decodeErr),
			}, nil
		}

		if body.AccessToken != "" {
			return &TokenResponse{
				AccessToken:  body.AccessToken,
				RefreshToken: body.RefreshToken,
				TokenType:    body.TokenType,
				ExpiresIn:    body.ExpiresIn,
				Scope:        body.Scope,
				IDToken:      body.IDToken,
			}, nil, nil
		}

		switch body.Error {
		case "authorization_pending", "slow_down", "expired_token", "access_denied", "authorization_declined":
			return nil, &oauth.DevicePollError{
				Code:        body.Error,
				Description: body.ErrorDescription,
				Interval:    body.Interval,
			}, nil
		default:
			return nil, &oauth.DevicePollError{
				Code:        body.Error,
				Description: body.ErrorDescription,
				Cause: fmt.Errorf("token request failed: %s - %s",
					sanitizeControlChars(body.Error), sanitizeControlChars(body.ErrorDescription)),
			}, nil
		}
	})
	if err != nil {
		switch {
		case errors.Is(err, oauth.ErrDeviceCodeExpired):
			return nil, fmt.Errorf("device code expired, please try again: %w", ErrTimeout)
		case errors.Is(err, oauth.ErrDeviceAccessDenied):
			return nil, fmt.Errorf("user denied access: %w", ErrUserCancelled)
		case errors.Is(err, context.DeadlineExceeded):
			return nil, fmt.Errorf("authentication timed out: %w", ErrTimeout)
		case errors.Is(err, context.Canceled):
			return nil, fmt.Errorf("authentication cancelled: %w", ErrUserCancelled)
		default:
			return nil, err
		}
	}

	return tokenResp, nil
}
