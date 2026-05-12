// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/client/tailscale"
)

const (
	certFilename = "cert.pem"
	keyFilename  = "key.pem"

	certRenewThreshold  = 30 * 24 * time.Hour
	certRefreshInterval = 1 * time.Hour
)

// writeCertPair fetches a cert/key pair from tsnet's LocalClient and writes
// them atomically under dir as cert.pem and key.pem.
func writeCertPair(ctx context.Context, lc *tailscale.LocalClient, hostname, dir string) error {
	certPEM, keyPEM, err := lc.CertPair(ctx, hostname)
	if err != nil {
		return fmt.Errorf("CertPair(%q): %w", hostname, err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// Key first, then cert: app-side watchers key off cert.pem mtime.
	if err := writeAtomic(filepath.Join(dir, keyFilename), keyPEM, 0o640); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if err := writeAtomic(filepath.Join(dir, certFilename), certPEM, 0o640); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	return nil
}

// writeAtomic writes data via a temp file + rename so readers never observe
// a partially-written file.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadLeafNotAfter parses dir/cert.pem and returns the leaf cert's NotAfter,
// or the zero time if the file is missing or unparseable.
func loadLeafNotAfter(dir string) time.Time {
	data, err := os.ReadFile(filepath.Join(dir, certFilename))
	if err != nil {
		return time.Time{}
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}
	}
	return leaf.NotAfter
}

// startCertRefresher loops until ctx.Done, re-fetching the cert pair when the
// on-disk cert is missing or within certRenewThreshold of NotAfter. CertPair
// is cached by tsnet so the no-op case is cheap. Failures are logged but
// never crash the daemon.
func startCertRefresher(ctx context.Context, lc *tailscale.LocalClient, hostname, dir string) {
	ticker := time.NewTicker(certRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			notAfter := loadLeafNotAfter(dir)
			if !notAfter.IsZero() && time.Until(notAfter) > certRenewThreshold {
				continue
			}
			if err := writeCertPair(ctx, lc, hostname, dir); err != nil {
				log.Printf("tls: refresh failed for %s: %v", hostname, err)
				continue
			}
			log.Printf("tls: refreshed cert for %s (expires %s)",
				hostname, loadLeafNotAfter(dir).Format(time.RFC3339))
		}
	}
}
