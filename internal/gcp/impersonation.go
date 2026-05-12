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

	resp, err := p.httpClient.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("impersonation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("impersonation denied: ensure source identity has roles/iam.serviceAccountTokenCreator on %s", targetSA)
	}

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		msg := ""
		if errObj, ok := errBody["error"].(map[string]any); ok {
			if s, ok := errObj["message"].(string); ok {
				msg = s
			}
		}
		if msg == "" {
			msg = fmt.Sprintf("%v", errBody)
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
	if err := json.NewDecoder(resp.Body).Decode(&impResp); err != nil {
		return nil, fmt.Errorf("parsing impersonation response: %w", err)
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
		Flow:        auth.Flow("impersonation"),
	}, nil
}

// getImpersonatedToken acquires a token for the impersonated service account.
func (p *Plugin) getImpersonatedToken(ctx context.Context, sourceAccessToken, scope string, forceRefresh bool) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	targetSA := p.config.ImpersonateServiceAccount

	// Determine scopes
	scopes := []string{scope}
	if scope == "" {
		scopes = p.config.DefaultScopes
	}

	// Check cache for impersonated token
	impersonateFingerprint := fingerprintHash(targetSA)
	if !forceRefresh {
		hostClient := p.hostClient(ctx)
		if hostClient != nil {
			cacheKey := buildCacheKey("impersonation", impersonateFingerprint, scope)
			cached, cacheErr := cacheGet(ctx, hostClient, cacheKey)
			if cacheErr == nil && cached != nil && cached.IsValidFor(DefaultMinValidFor) {
				lgr.V(1).Info("using cached impersonated token",
					"targetServiceAccount", targetSA,
					"scope", scope,
				)
				return cached, nil
			}
		}
	}

	// Impersonate
	token, err := p.impersonateServiceAccount(ctx, sourceAccessToken, targetSA, scopes)
	if err != nil {
		return nil, err
	}

	// Propagate SessionID from stored metadata so cache entries group correctly.
	if metadata, metaErr := p.loadMetadata(ctx); metaErr == nil && metadata != nil {
		token.SessionID = metadata.SessionID
	}

	// Cache the impersonated token
	hostClient := p.hostClient(ctx)
	if hostClient != nil {
		cacheKey := buildCacheKey("impersonation", impersonateFingerprint, scope)
		if cacheSetErr := cacheSet(ctx, hostClient, cacheKey, token); cacheSetErr != nil {
			lgr.V(1).Info("failed to cache impersonated token", "error", cacheSetErr)
		}
	}

	return token, nil
}
