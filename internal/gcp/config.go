// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package gcp implements the GCP auth handler plugin for scafctl.
package gcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/oakwood-commons/httpc"
)

const (
	// DefaultADCClientID is Google's well-known OAuth client ID for Application Default Credentials.
	// This is the same client ID used by gcloud for `gcloud auth application-default login`.
	// It is public and safe to embed: https://cloud.google.com/sdk/docs/authorizing
	DefaultADCClientID = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com" //nolint:gosec // Google's public ADC client ID, not a credential

	// DefaultADCClientSecret is the corresponding client secret for the default ADC OAuth client.
	// Despite the name, this is not confidential -- it is required by the OAuth protocol for
	// installed/desktop applications but provides no security benefit.
	DefaultADCClientSecret = "d-FL95Q19q7MQmFpd7hHD0Ty" //nolint:gosec // Google's public ADC client secret, not a credential
)

// Config holds GCP-specific configuration.
type Config struct {
	// HTTPClient carries optional HTTP client overrides forwarded by the host
	// under auth.gcp.httpClient / profiles.<name>.httpClient. Nil keeps the
	// plugin's own defaults.
	HTTPClient *httpc.AppConfig `json:"httpClient,omitempty" yaml:"httpClient,omitempty"`

	// ClientID is the OAuth 2.0 client ID for the ADC browser and device code flows.
	ClientID string `json:"clientId,omitempty" yaml:"clientId,omitempty"`

	// ClientSecret is the OAuth 2.0 client secret (not confidential for desktop apps).
	ClientSecret string `json:"clientSecret,omitempty" yaml:"clientSecret,omitempty"` //nolint:gosec // G117: not a hardcoded credential, it's a config field

	// DefaultScopes are the default OAuth scopes requested during login.
	DefaultScopes []string `json:"defaultScopes,omitempty" yaml:"defaultScopes,omitempty"`

	// ImpersonateServiceAccount is the target service account email for impersonation.
	// When set, all token requests will impersonate this service account.
	ImpersonateServiceAccount string `json:"impersonateServiceAccount,omitempty" yaml:"impersonateServiceAccount,omitempty"`

	// Project is the default GCP project (informational, stored in metadata).
	Project string `json:"project,omitempty" yaml:"project,omitempty"`

	// ServiceAccountKeyFile is the path to a GCP service account key JSON file.
	// When set in config or a profile, takes precedence over GOOGLE_APPLICATION_CREDENTIALS.
	ServiceAccountKeyFile string `json:"serviceAccountKeyFile,omitempty" yaml:"serviceAccountKeyFile,omitempty"`

	// ExternalAccountFile is the path to a workload identity federation config file.
	// When set in config or a profile, takes precedence over GOOGLE_EXTERNAL_ACCOUNT.
	ExternalAccountFile string `json:"externalAccountFile,omitempty" yaml:"externalAccountFile,omitempty"`

	// setFields tracks which JSON keys were explicitly provided with non-empty
	// values during unmarshaling.
	setFields map[string]bool `json:"-" yaml:"-"`
}

// UnmarshalJSON implements custom JSON unmarshaling that tracks which fields
// were explicitly present in the input so profileOrEnv can distinguish
// configured values from unset fields.
func (c *Config) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.setFields = make(map[string]bool, len(raw))
	for k, v := range raw {
		trimmed := string(bytes.TrimSpace(v))
		if trimmed != `""` && trimmed != "null" {
			c.setFields[k] = true
		}
	}

	type alias Config
	return json.Unmarshal(data, (*alias)(c))
}

// WasSet reports whether jsonField was explicitly provided with a non-empty
// value in the unmarshaled JSON configuration.
func (c *Config) WasSet(jsonField string) bool {
	if c == nil || c.setFields == nil {
		return false
	}
	return c.setFields[jsonField]
}

// profileOrEnv returns configVal when set in configuration (either via JSON
// unmarshaling or direct struct construction), falling back to envVar otherwise.
func (c *Config) profileOrEnv(configVal, jsonField, envVar string) string {
	if c != nil && (c.WasSet(jsonField) || configVal != "") {
		return configVal
	}
	return os.Getenv(envVar)
}

// DefaultConfig returns the default GCP configuration.
func DefaultConfig() *Config {
	return &Config{
		ClientID:     "",
		ClientSecret: "",
		DefaultScopes: []string{
			"openid",
			"email",
			"profile",
			"https://www.googleapis.com/auth/cloud-platform",
		},
	}
}

// parseHandlerConfig parses and validates raw JSON handler settings on top of
// DefaultConfig().
func parseHandlerConfig(raw []byte) (*Config, error) {
	cfg := DefaultConfig()
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse handler config: %w", err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.ImpersonateServiceAccount != "" {
		if len(c.ImpersonateServiceAccount) < 6 || !strings.Contains(c.ImpersonateServiceAccount, "@") {
			return fmt.Errorf("impersonateServiceAccount must be a valid service account email")
		}
	}
	return nil
}
