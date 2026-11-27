// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package gcp implements the GCP auth handler plugin for scafctl.
// This file implements service account impersonation via the IAM Credentials API.
package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
)

const (
	// iamCredentialsEndpoint is the base URL for the IAM Credentials API.
	iamCredentialsEndpoint = "https://iamcredentials.googleapis.com/v1" //nolint:gosec // G101: not a hardcoded credential
)

// ImpersonationRequest is the request body for generateAccessToken.
type ImpersonationRequest struct {
	Scope    []string `json:"scope"`
	Lifetime string   `json:"lifetime"`
}

// ImpersonationResponse is the response from generateAccessToken.
type ImpersonationResponse struct {
	AccessToken string `json:"accessToken"` //nolint:gosec // G117: not a hardcoded credential
	ExpireTime  string `json:"expireTime"`
}

// impersonateServiceAccount acquires an access token by impersonating a service account.
func (p *Plugin) impersonateServiceAccount(ctx context.Context, sourceToken, targetSA string, scopes []string) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("impersonating service account",
		"targetServiceAccount", targetSA,
		"scopes", scopes,
	)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/projects/-/serviceAccounts/%s:generateAccessToken",
		iamCredentialsEndpoint, url.PathEscape(targetSA))

	reqBody := ImpersonationRequest{
		Scope:    scopes,
		Lifetime: "3600s",
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("encoding impersonation request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("creating impersonation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sourceToken)

	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("impersonation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("impersonation denied: ensure source identity has roles/iam.serviceAccountTokenCreator on %s", targetSA)
	}

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errBody)
		msg := ""
		if errObj, ok := errBody["error"].(map[string]any); ok {
			if s, ok := errObj["message"].(string); ok {
				msg = sanitizeControlChars(s)
			}
		}
		if msg == "" {
			msg = sanitizeControlChars(fmt.Sprintf("%v", errBody))
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf(
				"impersonation failed: source identity is not authenticated (401): %s. "+
					"Re-authenticate with: %s auth login %s",
				msg, p.binaryName(), HandlerName)
		}
		return nil, fmt.Errorf("impersonation failed (status %d): %s", resp.StatusCode, msg)
	}

	var impResp ImpersonationResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&impResp); err != nil {
		return nil, fmt.Errorf("parsing impersonation response: %w", err)
	}
	if impResp.AccessToken == "" {
		return nil, fmt.Errorf("impersonation failed: endpoint returned empty accessToken")
	}

	// Parse the expiry time
	expireTime, err := time.Parse(time.RFC3339, impResp.ExpireTime)
	if err != nil {
		expireTime = time.Now().Add(time.Hour)
	}

	lgr.V(1).Info("impersonation successful",
		"targetServiceAccount", targetSA,
		"expiresAt", expireTime,
	)

	return &auth.Token{
		AccessToken: impResp.AccessToken,
		TokenType:   "Bearer",
		ExpiresAt:   expireTime,
		Scope:       strings.Join(scopes, " "),
		Flow:        auth.FlowInteractive,
	}, nil
}

// getImpersonatedToken acquires a token for the impersonated service account.
func (p *Plugin) getImpersonatedToken(ctx context.Context, sourceAccessToken, scope string, forceRefresh bool) (*auth.Token, error) {
	return p.getImpersonatedTokenWithSource(ctx, &auth.Token{AccessToken: sourceAccessToken}, "", scope, forceRefresh, DefaultMinValidFor)
}

func resolveImpersonationSourceIdentity(cfg *Config, flow auth.Flow, capturedIdentity string, matchedMetadata *TokenMetadata) string {
	if capturedIdentity != "" {
		return capturedIdentity
	}
	switch flow { //nolint:exhaustive // credential-file flows pass capturedIdentity directly without re-reading disk
	case auth.FlowInteractive, auth.FlowDeviceCode:
		if matchedMetadata != nil && matchedMetadata.ClientID != "" {
			return matchedMetadata.ClientID
		}
		if cfg != nil && cfg.ClientID != "" {
			return cfg.ClientID
		}
		return DefaultADCClientID
	}
	return ""
}

func (p *Plugin) getImpersonatedTokenWithSource(ctx context.Context, sourceToken *auth.Token, sourceIdentity string, scope string, forceRefresh bool, minValidFor time.Duration) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}

	if minValidFor <= 0 {
		minValidFor = DefaultMinValidFor
	}

	targetSA := cfg.ImpersonateServiceAccount

	// Determine scopes
	scopes := []string{scope}
	if scope == "" {
		scopes = cfg.DefaultScopes
	}

	var sessionID string
	var effectiveFlow auth.Flow
	var hasExplicitSourceFlow bool
	var matchedMetadata *TokenMetadata
	if sourceToken != nil {
		sessionID = sourceToken.SessionID
		effectiveFlow = sourceToken.Flow
		hasExplicitSourceFlow = sourceToken.Flow != ""
	}
	if !hasExplicitSourceFlow {
		if metadata, metaErr := p.loadMetadata(ctx); metaErr == nil && metadata != nil {
			matchedMetadata = metadata
			if sessionID == "" {
				sessionID = metadata.SessionID
			}
			if effectiveFlow == "" {
				effectiveFlow = metadata.Flow
			}
		}
	}
	if effectiveFlow == "" {
		effectiveFlow = auth.FlowInteractive
	}

	// Partition impersonated token cache by target SA AND the immutable source
	// identity/session captured at source-token acquisition time (preserving
	// targetSA-only fingerprint only for legacy direct getImpersonatedToken
	// helper calls where neither sourceToken.Flow nor stored metadata is present).
	impersonateFingerprint := fingerprintHash(targetSA)
	if hasExplicitSourceFlow || sessionID != "" {
		impersonateFingerprint = fingerprintHash(
			targetSA + "|" + string(effectiveFlow) + "|" + sessionID + "|" + resolveImpersonationSourceIdentity(cfg, effectiveFlow, sourceIdentity, matchedMetadata),
		)
	}

	prefix := p.tokenCachePrefix(ctx)
	cacheKey := buildCacheKey("impersonation", impersonateFingerprint, scope)
	if !forceRefresh {
		if hostClient := p.hostClient(ctx); hostClient != nil {
			cached, cacheErr := cacheGetWithPrefix(ctx, hostClient, prefix, cacheKey)
			if cacheErr == nil && cached != nil && cached.IsValidFor(minValidFor) && cached.SessionID == sessionID {
				if cached.Flow == "" || cached.Flow == auth.Flow("impersonation") {
					cached.Flow = effectiveFlow
				}
				lgr.V(1).Info("using cached impersonated token",
					"targetServiceAccount", targetSA,
					"scope", scope,
				)
				return cached, nil
			}
		}
	}

	var sourceAccessToken string
	if sourceToken != nil {
		sourceAccessToken = sourceToken.AccessToken
	}

	// Impersonate
	token, err := p.impersonateServiceAccount(ctx, sourceAccessToken, targetSA, scopes)
	if err != nil {
		return nil, err
	}

	token.Flow = effectiveFlow
	if sessionID != "" {
		token.SessionID = sessionID
	}

	// Cache the impersonated token if the session is still current
	p.cacheTokenForSession(ctx, cacheKey, token)

	return token, nil
}
