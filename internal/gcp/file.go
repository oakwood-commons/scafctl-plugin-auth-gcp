// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxCredentialFileBytes bounds local credential configuration and token files.
const maxCredentialFileBytes = 1 << 20 // 1 MiB

func openCredentialRoot(path string) (*os.Root, string, error) {
	cleanPath := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(cleanPath); err == nil {
		cleanPath = resolved
	}
	dir := filepath.Dir(cleanPath)
	safeFilename := filepath.Base(cleanPath)
	if safeFilename == "." || safeFilename == ".." || safeFilename == string(filepath.Separator) {
		return nil, "", fmt.Errorf("invalid credential file path")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	return root, safeFilename, nil
}

// readCredentialFile reads a local credential or token file through a
// directory-scoped os.Root handle and validated base filename.
func readCredentialFile(path string) ([]byte, error) {
	root, safeFilename, err := openCredentialRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(safeFilename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("credential path %q is a directory", safeFilename)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxCredentialFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCredentialFileBytes {
		return nil, fmt.Errorf("credential file exceeds maximum size (%d bytes)", maxCredentialFileBytes)
	}
	return data, nil
}

// statCredentialFile checks file metadata through a directory-scoped os.Root
// handle and validated base filename.
func statCredentialFile(path string) (os.FileInfo, error) {
	root, safeFilename, err := openCredentialRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	return root.Stat(safeFilename)
}
