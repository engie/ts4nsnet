// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
)

// fdTUN is a minimal tun.Device wrapping a raw TUN file descriptor.
// The TUN device was created inside the container's network namespace on a
// sacrificial goroutine. The fd works across namespaces for read/write
// since it's bound to the interface at creation time. We can't use
// wireguard-go's CreateTUNFromFile because its ioctls require being in
// the same netns.
type fdTUN struct {
	file   *os.File
	name   string
	mtu    int
	events chan tun.Event

	closeOnce sync.Once
}

func newFDTUN(file *os.File, name string, mtu int) *fdTUN {
	t := &fdTUN{
		file:   file,
		name:   name,
		mtu:    mtu,
		events: make(chan tun.Event, 1),
	}
	t.events <- tun.EventUp
	return t
}

func (t *fdTUN) File() *os.File { return t.file }

func (t *fdTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// Read a single packet from the TUN fd.
	n, err := t.file.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *fdTUN) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		if _, err := t.file.Write(pkt); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

func (t *fdTUN) MTU() (int, error) { return t.mtu, nil }

func (t *fdTUN) Name() (string, error) { return t.name, nil }

func (t *fdTUN) Events() <-chan tun.Event { return t.events }

func (t *fdTUN) BatchSize() int { return 1 }

func (t *fdTUN) Close() error {
	var err error
	t.closeOnce.Do(func() {
		t.events <- tun.EventDown
		close(t.events)
		err = t.file.Close()
	})
	return err
}
