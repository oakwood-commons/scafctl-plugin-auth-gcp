// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package gcp implements the GCP auth handler plugin for scafctl.
// This file implements the service account key JWT assertion flow.
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
	"github.com/golang-jwt/jwt/v5"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

const (
	// EnvGoogleApplicationCredentials is the environment variable for service account key file path.
	EnvGoogleApplicationCredentials = "GOOGLE_APPLICATION_CREDENTIALS" //nolint:gosec // G101: not a hardcoded credential
)

// ErrNoServiceAccountConfigured is returned by GetServiceAccountKey when no
// service account credentials are configured.
var ErrNoServiceAccountConfigured = errors.New("no service account configured")

// ServiceAccountKey represents the JSON structure of a GCP service account key file.
type ServiceAccountKey struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"` //nolint:gosec // G117: not a hardcoded credential, it's a config field
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

func getServiceAccountKeyFromPath(path string, explicit bool) (*ServiceAccountKey, error) {
	if path == "" {
		return nil, ErrNoServiceAccountConfigured
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304/G703: path from operator config or GOOGLE_APPLICATION_CREDENTIALS
	if err != nil {
		return nil, fmt.Errorf("reading service account key file: %w", err)
	}

	var key ServiceAccountKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("parsing service account key file: %w", err)
	}

	if key.Type != "service_account" {
		if explicit {
			return nil, fmt.Errorf("serviceAccountKeyFile has unsupported credential type %q (expected \"service_account\")", sanitizeControlChars(key.Type))
		}
		return nil, ErrNoServiceAccountConfigured
	}

	return &key, nil
}

// GetServiceAccountKey reads and parses a service account key from the
// GOOGLE_APPLICATION_CREDENTIALS environment variable.
func GetServiceAccountKey() (*ServiceAccountKey, error) {
	return getServiceAccountKeyFromPath(os.Getenv(EnvGoogleApplicationCredentials), false)
}

// HasServiceAccountCredentials checks if service account credentials are configured in the environment.
func HasServiceAccountCredentials() bool {
	_, err := GetServiceAccountKey()
	return err == nil
}

func (p *Plugin) getServiceAccountKeyForConfig(cfg *Config) (*ServiceAccountKey, error) {
	if cfg == nil {
		cfg = p.baseConfig()
	}
	explicitPath := cfg.profileOrEnv(cfg.ServiceAccountKeyFile, "serviceAccountKeyFile", "")
	if explicitPath != "" {
		return getServiceAccountKeyFromPath(explicitPath, true)
	}
	return getServiceAccountKeyFromPath(os.Getenv(EnvGoogleApplicationCredentials), false)
}

// serviceAccountLogin validates SA credentials by acquiring a token.
func (p *Plugin) serviceAccountLogin(ctx context.Context, req sdkplugin.LoginRequest) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting service account key login", "handler", HandlerName)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	key, err := p.getServiceAccountKeyForConfig(cfg)
	if err != nil {
		if errors.Is(err, ErrNoServiceAccountConfigured) {
			return nil, fmt.Errorf("service account credentials not configured: set serviceAccountKeyFile in config or %s environment variable",
				EnvGoogleApplicationCredentials)
		}
		return nil, fmt.Errorf("service account credentials error: %w", err)
	}

	scope := "https://www.googleapis.com/auth/cloud-platform"
	scopes := req.Scopes
	if len(scopes) > 0 {
		scope = strings.Join(scopes, " ")
	} else {
		scopes = []string{scope}
	}

	// Acquire a token to validate credentials
	token, err := p.acquireServiceAccountToken(ctx, key, scope)
	if err != nil {
		return nil, fmt.Errorf("service account authentication failed: %w", err)
	}

	claims := &auth.Claims{
		Issuer:   "https://accounts.google.com",
		Subject:  key.ClientEmail,
		Email:    key.ClientEmail,
		ClientID: key.ClientID,
		ObjectID: key.ClientID,
	}

	cacheKey := buildCacheKey(auth.FlowServicePrincipal, fingerprintHash(key.ClientEmail), scope)
	if _, err := p.storeMetadataAndSeedToken(ctx, claims, auth.FlowServicePrincipal, scopes, cacheKey, token); err != nil {
		return nil, fmt.Errorf("failed to store metadata: %w", err)
	}

	lgr.V(1).Info("service account authentication successful",
		"clientEmail", key.ClientEmail,
		"projectId", key.ProjectID,
	)

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// acquireServiceAccountToken acquires a token using JWT assertion flow.
func (p *Plugin) acquireServiceAccountToken(ctx context.Context, key *ServiceAccountKey, scope string) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	sourceLabel := EnvGoogleApplicationCredentials
	if cfg.profileOrEnv(cfg.ServiceAccountKeyFile, "serviceAccountKeyFile", "") != "" {
		sourceLabel = "serviceAccountKeyFile"
	}

	// Parse the private key using golang-jwt's built-in PEM parser.
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(key.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse service account private key: "+
				"the private_key field in %s may be malformed or not in PEM format: %w",
			sourceLabel, err)
	}

	// Use key.TokenURI when present, falling back to the default tokenEndpoint.
	audience := tokenEndpoint
	if key.TokenURI != "" {
		audience = key.TokenURI
	}

	// Create the JWT assertion with RS256 signing.
	now := time.Now()
	jwtClaims := jwt.MapClaims{
		"iss":   key.ClientEmail,
		"sub":   key.ClientEmail,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"scope": scope,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header["kid"] = key.PrivateKeyID

	assertion, err := token.SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("signing JWT: %w", err)
	}

	// Exchange JWT assertion for access token
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", assertion)

	lgr.V(1).Info("requesting token via JWT assertion",
		"clientEmail", key.ClientEmail,
		"scope", scope,
	)

	resp, err := httpClient.PostForm(ctx, audience, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&errResp)
		return nil, fmt.Errorf(
			"service account token request failed: %s - %s. "+
				"Verify the key in %s is valid, has not been revoked, "+
				"and the service account has the required IAM roles for the requested scope",
			sanitizeControlChars(errResp.Error), sanitizeControlChars(errResp.ErrorDescription), sourceLabel)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("service account token request failed: token endpoint returned empty access_token")
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	lgr.V(1).Info("acquired service account token",
		"expiresIn", tokenResp.ExpiresIn,
		"scope", scope,
	)

	return &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scope,
		Flow:        auth.FlowServicePrincipal,
	}, nil
}

// getServiceAccountToken gets a token using service account key, with caching.
func (p *Plugin) getServiceAccountToken(ctx context.Context, scope string, forceRefresh bool) (*auth.Token, error) {
	return p.getServiceAccountTokenWithMinValidFor(ctx, scope, forceRefresh, DefaultMinValidFor)
}

func (p *Plugin) getServiceAccountTokenWithMinValidFor(ctx context.Context, scope string, forceRefresh bool, minValidFor time.Duration) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	if minValidFor <= 0 {
		minValidFor = DefaultMinValidFor
	}

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	key, err := p.getServiceAccountKeyForConfig(cfg)
	if err != nil {
		if errors.Is(err, ErrNoServiceAccountConfigured) {
			return nil, ErrNotAuthenticated
		}
		return nil, fmt.Errorf("service account credentials error: %w", err)
	}

	fingerprint := fingerprintHash(key.ClientEmail)
	prefix := p.tokenCachePrefix(ctx)
	sessionID := p.readFlowSessionID(ctx, auth.FlowServicePrincipal, key.ClientEmail)
	cacheKey := buildCacheKey(auth.FlowServicePrincipal, fingerprint, scope)

	// Check cache first
	if !forceRefresh {
		if hostClient := p.hostClient(ctx); hostClient != nil {
			cached, cacheErr := cacheGetWithPrefix(ctx, hostClient, prefix, cacheKey)
			if cacheErr == nil && cached != nil && cached.IsValidFor(minValidFor) {
				if cached.SessionID == "" || sessionID == "" || cached.SessionID == sessionID {
					if cached.Flow == "" {
						cached.Flow = auth.FlowServicePrincipal
					}
					lgr.V(1).Info("using cached SA token", "scope", scope)
					return cached, nil
				}
			}
		}
	}

	// Acquire new token
	token, err := p.acquireServiceAccountToken(ctx, key, scope)
	if err != nil {
		return nil, err
	}
	token.SessionID = sessionID

	// Cache it if the session is still current
	p.cacheTokenForSession(ctx, cacheKey, token)

	return token, nil
}

// serviceAccountStatus returns the status for SA authentication.
func (p *Plugin) serviceAccountStatus(ctx context.Context) (*auth.Status, error) {
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	return p.serviceAccountStatusForConfig(cfg)
}

func (p *Plugin) serviceAccountStatusForConfig(cfg *Config) (*auth.Status, error) {
	key, err := p.getServiceAccountKeyForConfig(cfg)
	if err != nil {
		reason := ""
		if !errors.Is(err, ErrNoServiceAccountConfigured) {
			reason = err.Error()
		}
		return &auth.Status{ //nolint:nilerr // intentional: credential read errors mean not authenticated
			Authenticated: false,
			Flow:          auth.FlowServicePrincipal,
			Reason:        reason,
		}, nil
	}
	return p.serviceAccountStatusFromKey(cfg, key), nil
}

func (p *Plugin) serviceAccountStatusFromKey(cfg *Config, key *ServiceAccountKey) *auth.Status {
	var impersonated string
	if cfg != nil {
		impersonated = cfg.ImpersonateServiceAccount
	}
	return &auth.Status{
		Authenticated: true,
		Flow:          auth.FlowServicePrincipal,
		ClientID:      impersonated,
		Claims: &auth.Claims{
			Issuer:   "https://accounts.google.com",
			Subject:  key.ClientEmail,
			Email:    key.ClientEmail,
			ClientID: key.ClientID,
			ObjectID: key.ClientID,
			Name:     fmt.Sprintf("Service Account (%s)", key.ClientEmail),
		},
		IdentityType: auth.IdentityTypeServicePrincipal,
	}
}
