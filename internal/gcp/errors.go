// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package gcp

import "errors"

// Sentinel errors for authentication failure modes.
// These are local to the plugin since the SDK does not export them.
var (
	// ErrNotAuthenticated indicates no valid credentials are available.
	ErrNotAuthenticated = errors.New("not authenticated")

	// ErrTokenExpired indicates the token has expired or been revoked.
	ErrTokenExpired = errors.New("token expired")

	// ErrTimeout indicates an authentication operation timed out.
	ErrTimeout = errors.New("authentication timed out")

	// ErrUserCancelled indicates the user cancelled the authentication.
	ErrUserCancelled = errors.New("authentication cancelled by user")
)
