// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package gcp implements the GCP auth handler plugin for scafctl.
// This file implements the Workload Identity Federation STS token exchange flow.
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
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

const (
	// EnvGoogleExternalAccount is the environment variable for external account configuration.
	EnvGoogleExternalAccount = "GOOGLE_EXTERNAL_ACCOUNT"

	// stsEndpoint is the Google STS token exchange endpoint.
	stsEndpoint = "https://sts.googleapis.com/v1/token"
)

// ErrNoWorkloadIdentityConfigured is returned when no workload identity credentials are configured.
var ErrNoWorkloadIdentityConfigured = errors.New("no workload identity configured")

// ExternalAccountConfig represents the external account credential configuration JSON.
type ExternalAccountConfig struct {
	Type                           string           `json:"type"`
	Audience                       string           `json:"audience"`
	SubjectTokenType               string           `json:"subject_token_type"`
	TokenURL                       string           `json:"token_url"`
	ServiceAccountImpersonationURL string           `json:"service_account_impersonation_url,omitempty"`
	CredentialSource               CredentialSource `json:"credential_source"`
}

// CredentialSource defines where to read the subject token from.
type CredentialSource struct {
	File          string                  `json:"file,omitempty"`
	URL           string                  `json:"url,omitempty"`
	Headers       map[string]string       `json:"headers,omitempty"`
	EnvironmentID string                  `json:"environment_id,omitempty"`
	Format        *CredentialSourceFormat `json:"format,omitempty"`
	RegionURL     string                  `json:"region_url,omitempty"`
}

// CredentialSourceFormat defines the format of the credential source.
type CredentialSourceFormat struct {
	Type                  string `json:"type,omitempty"`
	SubjectTokenFieldName string `json:"subject_token_field_name,omitempty"`
}

// STSTokenResponse represents the response from the STS token exchange.
type STSTokenResponse struct {
	AccessToken     string `json:"access_token"` //nolint:gosec // G117: not a hardcoded credential
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

func getExternalAccountConfigFromPath(path string, explicit bool) (*ExternalAccountConfig, error) {
	if path == "" {
		return nil, ErrNoWorkloadIdentityConfigured
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304/G703: path from operator config or GOOGLE_EXTERNAL_ACCOUNT
	if err != nil {
		return nil, fmt.Errorf("reading external account config: %w", err)
	}

	var cfg ExternalAccountConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing external account config: %w", err)
	}

	if cfg.Type != "external_account" {
		if explicit {
			return nil, fmt.Errorf("externalAccountFile has unsupported credential type %q (expected \"external_account\")", sanitizeControlChars(cfg.Type))
		}
		return nil, ErrNoWorkloadIdentityConfigured
	}

	return &cfg, nil
}

// GetExternalAccountConfig reads and parses the external account configuration
// from the GOOGLE_EXTERNAL_ACCOUNT environment variable.
func GetExternalAccountConfig() (*ExternalAccountConfig, error) {
	return getExternalAccountConfigFromPath(os.Getenv(EnvGoogleExternalAccount), false)
}

// HasWorkloadIdentityCredentials checks if workload identity credentials are configured in the environment.
func HasWorkloadIdentityCredentials() bool {
	_, err := GetExternalAccountConfig()
	return err == nil
}

func (p *Plugin) getExternalAccountConfigForConfig(cfg *Config) (*ExternalAccountConfig, error) {
	if cfg == nil {
		cfg = p.baseConfig()
	}
	explicitPath := cfg.profileOrEnv(cfg.ExternalAccountFile, "externalAccountFile", "")
	if explicitPath != "" {
		return getExternalAccountConfigFromPath(explicitPath, true)
	}
	return getExternalAccountConfigFromPath(os.Getenv(EnvGoogleExternalAccount), false)
}

func workloadIdentityFingerprint(cfg *ExternalAccountConfig) string {
	if cfg == nil {
		return fingerprintHash("")
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return fingerprintHash(cfg.Audience + "|" + cfg.CredentialSource.File + "|" + cfg.CredentialSource.URL)
	}
	return fingerprintHash(string(data))
}

// readSubjectToken reads the subject token from the credential source.
func readSubjectToken(cfg *ExternalAccountConfig) (string, error) {
	if cfg.CredentialSource.File != "" {
		data, err := os.ReadFile(cfg.CredentialSource.File)
		if err != nil {
			return "", fmt.Errorf("reading subject token file: %w", err)
		}

		// Handle structured token formats
		if cfg.CredentialSource.Format != nil && cfg.CredentialSource.Format.Type == "json" {
			var tokenDoc map[string]any
			if err := json.Unmarshal(data, &tokenDoc); err != nil {
				return "", fmt.Errorf("parsing subject token JSON: %w", err)
			}
			fieldName := cfg.CredentialSource.Format.SubjectTokenFieldName
			if fieldName == "" {
				fieldName = "token"
			}
			tokenVal, ok := tokenDoc[fieldName]
			if !ok {
				return "", fmt.Errorf("subject token field %q not found in JSON", fieldName)
			}
			tokenStr, ok := tokenVal.(string)
			if !ok {
				return "", fmt.Errorf("subject token field %q is not a string", fieldName)
			}
			return tokenStr, nil
		}

		return strings.TrimSpace(string(data)), nil
	}

	if cfg.CredentialSource.URL != "" {
		return "", fmt.Errorf(
			"unsupported credential source in external account config: "+
				"URL-based credential sources are not yet supported. "+
				"Only file-based credential sources are supported")
	}

	return "", fmt.Errorf(
		"unsupported credential source in external account config: "+
			"no file or URL is configured under credential_source. "+
			"Check the external account JSON file referenced by externalAccountFile or %s",
		EnvGoogleExternalAccount)
}

// workloadIdentityLogin validates workload identity credentials by acquiring a token.
func (p *Plugin) workloadIdentityLogin(ctx context.Context, req sdkplugin.LoginRequest) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting workload identity federation login", "handler", HandlerName)

	handlerCfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, handlerCfg)

	extCfg, err := p.getExternalAccountConfigForConfig(handlerCfg)
	if err != nil {
		if errors.Is(err, ErrNoWorkloadIdentityConfigured) {
			return nil, fmt.Errorf("workload identity credentials not configured: set externalAccountFile in config or %s environment variable",
				EnvGoogleExternalAccount)
		}
		return nil, fmt.Errorf("workload identity credentials error: %w", err)
	}

	scope := "https://www.googleapis.com/auth/cloud-platform"
	scopes := req.Scopes
	if len(scopes) > 0 {
		scope = strings.Join(scopes, " ")
	} else {
		scopes = []string{scope}
	}

	// Acquire a token to validate credentials
	token, err := p.acquireWorkloadIdentityToken(ctx, extCfg, scope)
	if err != nil {
		return nil, fmt.Errorf("workload identity authentication failed: %w", err)
	}

	claims := &auth.Claims{
		Issuer:  "https://accounts.google.com",
		Subject: extCfg.Audience,
	}

	cacheKey := buildCacheKey(auth.FlowWorkloadIdentity, workloadIdentityFingerprint(extCfg), scope)
	if _, err := p.storeMetadataAndSeedToken(ctx, claims, auth.FlowWorkloadIdentity, scopes, cacheKey, token); err != nil {
		return nil, fmt.Errorf("failed to store metadata: %w", err)
	}

	lgr.V(1).Info("workload identity authentication successful",
		"audience", extCfg.Audience,
	)

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// acquireWorkloadIdentityToken acquires a token via STS token exchange.
func (p *Plugin) acquireWorkloadIdentityToken(ctx context.Context, cfg *ExternalAccountConfig, scope string) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	handlerCfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, err := p.httpClientForConfig(ctx, handlerCfg)
	if err != nil {
		return nil, err
	}

	// Read the subject token
	subjectToken, err := readSubjectToken(cfg)
	if err != nil {
		return nil, fmt.Errorf("reading subject token: %w", err)
	}

	// Exchange via STS
	endpoint := cfg.TokenURL
	if endpoint == "" {
		endpoint = stsEndpoint
	}

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("audience", cfg.Audience)
	data.Set("scope", scope)
	data.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("subject_token_type", cfg.SubjectTokenType)
	data.Set("subject_token", subjectToken)

	lgr.V(1).Info("requesting token via STS exchange",
		"endpoint", endpoint,
		"audience", cfg.Audience,
	)

	resp, err := httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("STS token exchange failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errResp)
		sourceLabel := EnvGoogleExternalAccount
		if handlerCfg.profileOrEnv(handlerCfg.ExternalAccountFile, "externalAccountFile", "") != "" {
			sourceLabel = "externalAccountFile"
		}
		return nil, fmt.Errorf(
			"STS token exchange failed: %s - %s. "+
				"Verify the audience, subject_token_type, and token_url in the external account config (%s) "+
				"and that the Workload Identity Pool is correctly configured in GCP IAM",
			sanitizeControlChars(errResp.Error), sanitizeControlChars(errResp.ErrorDescription), sourceLabel)
	}

	var stsResp STSTokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&stsResp); err != nil {
		return nil, fmt.Errorf("failed to parse STS response: %w", err)
	}
	if stsResp.AccessToken == "" {
		return nil, fmt.Errorf("STS token exchange failed: endpoint returned empty access_token")
	}

	expiresAt := time.Now().Add(time.Duration(stsResp.ExpiresIn) * time.Second)

	lgr.V(1).Info("acquired workload identity token", "expiresIn", stsResp.ExpiresIn)

	return &auth.Token{
		AccessToken: stsResp.AccessToken,
		TokenType:   stsResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scope,
		Flow:        auth.FlowWorkloadIdentity,
	}, nil
}

// getWorkloadIdentityToken gets a token using workload identity, with caching.
func (p *Plugin) getWorkloadIdentityToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	return p.getWorkloadIdentityTokenWithMinValidFor(ctx, scope, forceRefresh, DefaultMinValidFor)
}

func (p *Plugin) getWorkloadIdentityTokenWithMinValidFor(ctx context.Context, scope string, forceRefresh bool, minValidFor time.Duration) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	if minValidFor <= 0 {
		minValidFor = DefaultMinValidFor
	}

	handlerCfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, handlerCfg)

	extCfg, err := p.getExternalAccountConfigForConfig(handlerCfg)
	if err != nil {
		if errors.Is(err, ErrNoWorkloadIdentityConfigured) {
			return nil, ErrNotAuthenticated
		}
		return nil, fmt.Errorf("workload identity credentials error: %w", err)
	}

	fingerprint := workloadIdentityFingerprint(extCfg)
	prefix := p.tokenCachePrefix(ctx)
	sessionID := p.readFlowSessionID(ctx, auth.FlowWorkloadIdentity, extCfg.Audience)
	cacheKey := buildCacheKey(auth.FlowWorkloadIdentity, fingerprint, scope)

	// Check cache first
	if !forceRefresh {
		if hostClient := p.hostClient(ctx); hostClient != nil {
			cached, cacheErr := cacheGetWithPrefix(ctx, hostClient, prefix, cacheKey)
			if cacheErr == nil && cached != nil && cached.IsValidFor(minValidFor) {
				if cached.SessionID == "" || sessionID == "" || cached.SessionID == sessionID {
					if cached.Flow == "" {
						cached.Flow = auth.FlowWorkloadIdentity
					}
					lgr.V(1).Info("using cached WI token", "scope", scope)
					return cached, nil
				}
			}
		}
	}

	// Acquire new token
	token, err := p.acquireWorkloadIdentityToken(ctx, extCfg, scope)
	if err != nil {
		return nil, err
	}
	token.SessionID = sessionID

	// Cache it if the session is still current
	p.cacheTokenForSession(ctx, cacheKey, token)

	return token, nil
}

// workloadIdentityStatus returns the status for workload identity authentication.
func (p *Plugin) workloadIdentityStatus(ctx context.Context) (*auth.Status, error) {
	handlerCfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	return p.workloadIdentityStatusForConfig(handlerCfg)
}

func (p *Plugin) workloadIdentityStatusForConfig(handlerCfg *Config) (*auth.Status, error) {
	cfg, err := p.getExternalAccountConfigForConfig(handlerCfg)
	if err != nil {
		reason := ""
		if !errors.Is(err, ErrNoWorkloadIdentityConfigured) {
			reason = err.Error()
		}
		return &auth.Status{ //nolint:nilerr // intentional: credential read errors mean not authenticated
			Authenticated: false,
			Flow:          auth.FlowWorkloadIdentity,
			Reason:        reason,
		}, nil
	}
	return p.workloadIdentityStatusFromParsed(handlerCfg, cfg), nil
}

func (p *Plugin) workloadIdentityStatusFromParsed(handlerCfg *Config, cfg *ExternalAccountConfig) *auth.Status {
	tokenFile := cfg.CredentialSource.File

	// Verify credential source is accessible before reporting authenticated
	if tokenFile != "" {
		if _, err := os.Stat(tokenFile); err != nil {
			return &auth.Status{
				Authenticated: false,
				Flow:          auth.FlowWorkloadIdentity,
				Reason:        fmt.Sprintf("subject token file is not accessible: %v", err),
			}
		}
	} else if cfg.CredentialSource.URL == "" {
		return &auth.Status{
			Authenticated: false,
			Flow:          auth.FlowWorkloadIdentity,
			Reason:        "external account config has no credential_source file or url",
		}
	}

	var impersonated string
	if handlerCfg != nil {
		impersonated = handlerCfg.ImpersonateServiceAccount
	}

	return &auth.Status{
		Authenticated: true,
		Flow:          auth.FlowWorkloadIdentity,
		ClientID:      impersonated,
		Claims: &auth.Claims{
			Issuer:  "https://accounts.google.com",
			Subject: cfg.Audience,
			Name:    "Workload Identity Federation",
		},
		IdentityType: auth.IdentityTypeWorkloadIdentity,
		TokenFile:    tokenFile,
	}
}
