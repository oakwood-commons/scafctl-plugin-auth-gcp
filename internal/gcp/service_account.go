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

// GetServiceAccountKey reads and parses a service account key from the
// GOOGLE_APPLICATION_CREDENTIALS environment variable.
func GetServiceAccountKey() (*ServiceAccountKey, error) {
	path := os.Getenv(EnvGoogleApplicationCredentials)
	if path == "" {
		return nil, ErrNoServiceAccountConfigured
	}

	data, err := os.ReadFile(path) //nolint:gosec // G703: path from env var is expected
	if err != nil {
		return nil, fmt.Errorf("reading service account key file: %w", err)
	}

	var key ServiceAccountKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("parsing service account key file: %w", err)
	}

	if key.Type != "service_account" {
		return nil, ErrNoServiceAccountConfigured
	}

	return &key, nil
}

// HasServiceAccountCredentials checks if service account credentials are configured.
func HasServiceAccountCredentials() bool {
	_, err := GetServiceAccountKey()
	return err == nil
}

// serviceAccountLogin validates SA credentials by acquiring a token.
func (p *Plugin) serviceAccountLogin(ctx context.Context, req sdkplugin.LoginRequest) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting service account key login", "handler", HandlerName)

	key, err := GetServiceAccountKey()
	if err != nil {
		if errors.Is(err, ErrNoServiceAccountConfigured) {
			return nil, fmt.Errorf("service account credentials not configured: set %s environment variable",
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

	// Store metadata
	if err := p.storeMetadataOnly(ctx, claims, auth.FlowServicePrincipal, scopes); err != nil {
		lgr.V(1).Info("warning: failed to store metadata", "error", err)
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

	// Parse the private key using golang-jwt's built-in PEM parser.
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(key.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse service account private key: "+
				"the private_key field in %s may be malformed or not in PEM format: %w",
			EnvGoogleApplicationCredentials, err)
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

	resp, err := p.httpClient.PostForm(ctx, audience, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf(
			"service account token request failed: %s - %s. "+
				"Verify the key in %s is valid, has not been revoked, "+
				"and the service account has the required IAM roles for the requested scope",
			errResp.Error, errResp.ErrorDescription, EnvGoogleApplicationCredentials)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
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
	lgr := logr.FromContextOrDiscard(ctx)

	key, err := GetServiceAccountKey()
	if err != nil {
		return nil, ErrNotAuthenticated
	}

	fingerprint := fingerprintHash(key.ClientEmail)

	// Check cache first
	if !forceRefresh {
		hostClient := p.hostClient(ctx)
		if hostClient != nil {
			cacheKey := buildCacheKey(auth.FlowServicePrincipal, fingerprint, scope)
			cached, cacheErr := cacheGet(ctx, hostClient, cacheKey)
			if cacheErr == nil && cached != nil && cached.IsValidFor(DefaultMinValidFor) {
				lgr.V(1).Info("using cached SA token", "scope", scope)
				return cached, nil
			}
		}
	}

	// Acquire new token
	token, err := p.acquireServiceAccountToken(ctx, key, scope)
	if err != nil {
		return nil, err
	}

	// Cache it
	hostClient := p.hostClient(ctx)
	if hostClient != nil {
		cacheKey := buildCacheKey(auth.FlowServicePrincipal, fingerprint, scope)
		if cacheSetErr := cacheSet(ctx, hostClient, cacheKey, token); cacheSetErr != nil {
			lgr.V(1).Info("failed to cache SA token", "error", cacheSetErr)
		}
	}

	return token, nil
}

// serviceAccountStatus returns the status for SA authentication.
func (p *Plugin) serviceAccountStatus(_ context.Context) (*auth.Status, error) {
	key, err := GetServiceAccountKey()
	if err != nil {
		return &auth.Status{ //nolint:nilerr // intentional: credential read errors mean not authenticated
			Authenticated: false,
		}, nil
	}

	return &auth.Status{
		Authenticated: true,
		Claims: &auth.Claims{
			Issuer:   "https://accounts.google.com",
			Subject:  key.ClientEmail,
			Email:    key.ClientEmail,
			ClientID: key.ClientID,
			ObjectID: key.ClientID,
			Name:     fmt.Sprintf("Service Account (%s)", key.ClientEmail),
		},
		IdentityType: auth.IdentityTypeServicePrincipal,
	}, nil
}
