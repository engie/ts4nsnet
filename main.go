// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// ts4nsnet is a rootless container networking tool that acts as a drop-in
// replacement for slirp4netns. It creates a TUN device inside a container's
// network namespace and bridges traffic onto the tailnet via tsnet, making
// the container appear as its own ephemeral Tailscale node.
//
// Usage (via podman):
//
//	TS_AUTHKEY=tskey-auth-... TS_HOSTNAME=mycontainer \
//	  podman run --rm -it --network-cmd-path=/path/to/ts4nsnet --network slirp4netns alpine sh
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
)

// envConfig holds configuration read from environment variables.
type envConfig struct {
	AuthKey    string
	Hostname   string
	ExitNode   string
	ControlURL string
	StateDir   string
}

// parseEnvConfig reads and validates ts4nsnet configuration from environment
// variables. Returns an error if required variables are missing.
func parseEnvConfig() (envConfig, error) {
	c := envConfig{
		AuthKey:    os.Getenv("TS_AUTHKEY"),
		Hostname:   os.Getenv("TS_HOSTNAME"),
		ExitNode:   os.Getenv("TS_EXIT_NODE"),
		ControlURL: os.Getenv("TS_CONTROL_URL"),
		StateDir:   os.Getenv("TS_STATE_DIR"),
	}
	if c.AuthKey == "" {
		return c, fmt.Errorf("TS_AUTHKEY environment variable is required")
	}
	if c.Hostname == "" {
		return c, fmt.Errorf("TS_HOSTNAME environment variable is required")
	}
	return c, nil
}

// resolveNSPath returns the network namespace path. If netnsType is "path",
// nsArg is returned as-is. Otherwise it is treated as a PID and resolved to
// /proc/<pid>/ns/net.
func resolveNSPath(nsArg, netnsType string) (string, error) {
	if netnsType == "path" {
		return nsArg, nil
	}
	if _, err := strconv.Atoi(nsArg); err != nil {
		return "", fmt.Errorf("invalid PID %q: %w", nsArg, err)
	}
	return "/proc/" + nsArg + "/ns/net", nil
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("ts4nsnet: ")

	// Handle --help before normal flag parsing.
	for _, arg := range os.Args[1:] {
		if arg == "--help" || arg == "-h" {
			// Podman calls the binary with --help to verify it's a valid
			// slirp4netns replacement. It checks for "slirp4netns" in the output.
			fmt.Println("slirp4netns (ts4nsnet - tailscale container networking)")
			fmt.Println("Usage: ts4nsnet [OPTIONS] NSPATH TUNNAME")
			fmt.Println()
			fmt.Println("Options:")
			fmt.Println("  -c                  configure interface")
			fmt.Println("  -r FD               ready fd")
			fmt.Println("  -e FD               exit fd")
			fmt.Println("  --mtu MTU           MTU (default 1500)")
			fmt.Println("  --netns-type TYPE   namespace type (default path)")
			fmt.Println("  --cidr CIDR         CIDR (ignored)")
			fmt.Println("  --disable-host-loopback  disable host loopback (ignored)")
			fmt.Println("  --enable-sandbox    enable sandbox (ignored)")
			fmt.Println("  --enable-seccomp    enable seccomp (ignored)")
			fmt.Println("  --enable-ipv6       enable IPv6 (ignored, always enabled)")
			fmt.Println("  --api-socket PATH   API socket (ignored)")
			os.Exit(0)
		}
	}

	// Slirp4netns-compatible flags. Podman constructs these.
	configure := flag.Bool("c", false, "configure interface")
	readyFD := flag.Int("r", -1, "ready fd")
	exitFD := flag.Int("e", -1, "exit fd")
	mtu := flag.Int("mtu", 1500, "MTU")
	netnsType := flag.String("netns-type", "path", "namespace type")

	// Ignored slirp4netns flags (accepted for compatibility).
	flag.String("cidr", "", "ignored")
	flag.Bool("disable-host-loopback", false, "ignored")
	flag.Bool("enable-sandbox", false, "ignored")
	flag.Bool("enable-seccomp", false, "ignored")
	flag.Bool("enable-ipv6", false, "ignored")
	flag.String("api-socket", "", "ignored")

	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		log.Fatalf("usage: ts4nsnet [OPTIONS] NSPATH TUNNAME")
	}
	nsPath, err := resolveNSPath(args[0], *netnsType)
	if err != nil {
		log.Fatalf("resolving namespace path: %v", err)
	}
	tunName := args[1]

	cfg, err := parseEnvConfig()
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Create TUN device inside the container's network namespace.
	tunDev, err := createTUNInNamespace(nsPath, tunName, *mtu)
	if err != nil {
		log.Fatalf("creating TUN in namespace: %v", err)
	}

	// Set up a state directory for tsnet. If TS_STATE_DIR is set, use it
	// directly. Otherwise create a per-instance temp directory that is
	// cleaned up on shutdown to avoid host persistence and collisions
	// between concurrent containers.
	stateDir := cfg.StateDir
	if stateDir == "" {
		d, err := os.MkdirTemp("", "ts4nsnet-*")
		if err != nil {
			log.Fatalf("creating state directory: %v", err)
		}
		stateDir = d
		defer os.RemoveAll(stateDir)
	}

	// Build tsnet server with the real TUN device.
	srv := &tsnet.Server{
		Hostname:  cfg.Hostname,
		AuthKey:   cfg.AuthKey,
		Ephemeral: true,
		Store:     new(mem.Store),
		Tun:       tunDev,
		Dir:       stateDir,
	}
	if cfg.ControlURL != "" {
		srv.ControlURL = cfg.ControlURL
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	status, err := srv.Up(ctx)
	if err != nil {
		log.Fatalf("tsnet.Up: %v", err)
	}

	// Extract assigned tailnet IPs.
	var ip4, ip6 netip.Addr
	for _, ip := range status.TailscaleIPs {
		if ip.Is4() && !ip4.IsValid() {
			ip4 = ip
		}
		if ip.Is6() && !ip6.IsValid() {
			ip6 = ip
		}
	}
	log.Printf("tailnet IPs: v4=%v v6=%v", ip4, ip6)

	// Set exit node if requested.
	if cfg.ExitNode != "" {
		exitIP, err := netip.ParseAddr(cfg.ExitNode)
		if err != nil {
			log.Fatalf("parsing TS_EXIT_NODE %q: %v", cfg.ExitNode, err)
		}
		lc, err := srv.LocalClient()
		if err != nil {
			log.Fatalf("getting local client: %v", err)
		}
		_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				ExitNodeIP: exitIP,
			},
			ExitNodeIPSet: true,
		})
		if err != nil {
			log.Fatalf("setting exit node: %v", err)
		}
		log.Printf("exit node set to %v", exitIP)
	}

	// Configure the interface inside the container namespace.
	if *configure {
		if err := configureInterface(nsPath, tunName, ip4, ip6, *mtu); err != nil {
			log.Fatalf("configuring interface: %v", err)
		}
		log.Printf("interface %s configured", tunName)
	}

	// Signal readiness to podman.
	if *readyFD >= 0 {
		f := os.NewFile(uintptr(*readyFD), "ready-fd")
		if f != nil {
			if _, err := f.Write([]byte("1")); err != nil {
				log.Fatalf("writing to ready fd: %v", err)
			}
			f.Close()
		}
	}

	// Wait for exit signal: exit-fd HUP, SIGTERM, or SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	exitCh := make(chan struct{})
	if *exitFD >= 0 {
		f := os.NewFile(uintptr(*exitFD), "exit-fd")
		if f != nil {
			go func() {
				buf := make([]byte, 1)
				// Read blocks until HUP/EOF.
				if _, err := f.Read(buf); err != nil {
					log.Printf("exit fd read error: %v", err)
				}
				close(exitCh)
			}()
		}
	}

	select {
	case <-sigCh:
		log.Printf("received signal, shutting down")
	case <-exitCh:
		log.Printf("exit fd closed, shutting down")
	}

	srv.Close()
}

