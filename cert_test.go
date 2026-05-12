// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteAtomicCreatesFileWithMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := writeAtomic(path, []byte("hello"), 0o640); err != nil {
		t.Fatalf("writeAtomic: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", info.Mode().Perm())
	}

	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp sibling should not remain: stat err = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("contents = %q, want %q", data, "hello")
	}
}

func TestLoadLeafNotAfter(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file returns zero", func(t *testing.T) {
		if got := loadLeafNotAfter(dir); !got.IsZero() {
			t.Errorf("loadLeafNotAfter on empty dir = %v, want zero", got)
		}
	})

	t.Run("parses a real cert", func(t *testing.T) {
		notAfter := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)
		certPEM := mintTestCert(t, notAfter)
		if err := os.WriteFile(filepath.Join(dir, certFilename), certPEM, 0o640); err != nil {
			t.Fatalf("write cert: %v", err)
		}

		got := loadLeafNotAfter(dir)
		if !got.Equal(notAfter) {
			t.Errorf("loadLeafNotAfter = %v, want %v", got, notAfter)
		}
	})

	t.Run("garbage file returns zero", func(t *testing.T) {
		bad := t.TempDir()
		if err := os.WriteFile(filepath.Join(bad, certFilename), []byte("not a pem"), 0o640); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := loadLeafNotAfter(bad); !got.IsZero() {
			t.Errorf("loadLeafNotAfter on garbage = %v, want zero", got)
		}
	})
}

// mintTestCert produces a self-signed leaf cert in PEM form, expiring at the
// given time. Used to exercise loadLeafNotAfter without needing a real CA.
func mintTestCert(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
