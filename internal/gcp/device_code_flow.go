// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
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

	lgr.V(1).Info("device code obtained",
		"userCode", deviceCode.UserCode,
		"verificationURL", deviceCode.VerificationURL,
	)

	// Step 2: Notify callback with device code info for CLI display
	if deviceCodeCb != nil {
		deviceCodeCb(sdkplugin.DeviceCodePrompt{
			UserCode:        deviceCode.UserCode,
			VerificationURI: deviceCode.VerificationURL,
			Message:         "Enter this code to authenticate with Google Cloud",
		})
	}

	// Step 3: Poll for token
	tokenResp, err := p.pollGCPDeviceToken(ctx, deviceCode, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("device code polling failed: %w", err)
	}

	// Step 4: Store credentials
	scopeStr := strings.Join(scopes, " ")
	if err := p.storeCredentials(ctx, tokenResp, auth.FlowDeviceCode, scopes, "", clientID); err != nil {
		return nil, fmt.Errorf("failed to store credentials: %w", err)
	}

	// Cache the access token
	if tokenResp.AccessToken != "" {
		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		hostClient := p.hostClient(ctx)
		if hostClient != nil {
			cacheKey := buildCacheKey(auth.FlowDeviceCode, fingerprintHash(clientID), scopeStr)
			_ = cacheSet(ctx, hostClient, cacheKey, &auth.Token{
				AccessToken: tokenResp.AccessToken,
				TokenType:   tokenResp.TokenType,
				ExpiresAt:   expiresAt,
				Scope:       scopeStr,
				Flow:        auth.FlowDeviceCode,
			})
		}
	}

	// Extract claims
	claims, err := extractClaims(tokenResp)
	if err != nil {
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
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", strings.Join(scopes, " "))

	resp, err := p.httpClient.PostForm(ctx, deviceCodeEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("device code request failed (%d): %s - %s",
			resp.StatusCode, errResp.Error, errResp.ErrorDescription)
	}

	var deviceCode DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceCode); err != nil {
		return nil, fmt.Errorf("failed to parse device code response: %w", err)
	}

	return &deviceCode, nil
}

// pollGCPDeviceToken polls Google's token endpoint until the user completes
// authentication or the device code expires.
func (p *Plugin) pollGCPDeviceToken(ctx context.Context, deviceCode *DeviceCodeResponse, clientID, clientSecret string) (*TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	interval := time.Duration(deviceCode.Interval) * time.Second
	if interval < defaultDeviceCodePollInterval {
		interval = defaultDeviceCodePollInterval
	}

	ticker := p.clock.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				return nil, fmt.Errorf("authentication timed out: %w", ErrTimeout)
			}
			return nil, fmt.Errorf("authentication cancelled: %w", ErrUserCancelled)
		case <-ticker.C():
			data := url.Values{}
			data.Set("client_id", clientID)
			if clientSecret != "" {
				data.Set("client_secret", clientSecret)
			}
			data.Set("device_code", deviceCode.DeviceCode)
			data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

			resp, err := p.httpClient.PostForm(ctx, tokenEndpoint, data)
			if err != nil {
				lgr.V(1).Info("transient network error during device code poll, continuing", "error", err)
				continue
			}

			var body struct {
				TokenResponse
				TokenErrorResponse
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				_ = resp.Body.Close()
				return nil, fmt.Errorf("failed to parse token response: %w", err)
			}
			_ = resp.Body.Close()

			// Success: access_token present
			if body.AccessToken != "" {
				return &TokenResponse{
					AccessToken:  body.AccessToken,
					RefreshToken: body.RefreshToken,
					TokenType:    body.TokenType,
					ExpiresIn:    body.ExpiresIn,
					Scope:        body.Scope,
					IDToken:      body.IDToken,
				}, nil
			}

			// Handle polling errors per RFC 8628
			switch body.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				interval += slowDownIncrement
				ticker.Reset(interval)
				lgr.V(1).Info("slow_down received, increasing poll interval", "newInterval", interval)
				continue
			case "expired_token":
				return nil, fmt.Errorf("device code expired, please try again: %w", ErrTimeout)
			case "access_denied":
				return nil, fmt.Errorf("user denied access: %w", ErrUserCancelled)
			default:
				return nil, fmt.Errorf("token request failed: %s - %s", body.Error, body.ErrorDescription)
			}
		}
	}
}
