# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ts4nsnet is a drop-in replacement for slirp4netns that bridges rootless container traffic onto a Tailscale network (tailnet) via the `tsnet` library. It creates a TUN device inside a container's network namespace and makes containers appear as ephemeral Tailscale nodes. Designed for use with podman.

All source files are Linux-only (`//go:build linux`).

## Build & Test Commands

```bash
# Build
go build -o ts4nsnet .

# Lint
go vet ./...

# Tier 1: Unit tests (no root, no network)
go test -run 'TestResolveNSPath|TestParseEnvConfig|TestValidateMTU|TestFdTUNCloseEvents|TestIgnoredFlags|TestReadPidfile|TestValidatePIDNetNS|TestContainerPID|TestSSHPayloadParsing|TestSSHHostKeyPersistence|TestParseSSHAllow|TestSSHAllowlist|TestAcceptEnvPair|TestMatchAcceptEnvPattern|TestParseAcceptEnv|TestIsAllowedEnv|TestParsePasswdUser|TestBaseEnvForUser|TestDiscoverContainers' -v ./...

# Tier 2: Integration tests (no root, fake control + chanTUN)
go test -run 'TestTsnetConnectsToControl|TestTwoNodesCanCommunicate|TestExitNodeConfig|TestSSHServerConnects' -v ./...

# Tier 3: Namespace tests (requires root)
sudo go test -run 'TestCreateTUNInNamespace|TestConfigureInterface' -v ./...

# Tier 4: Full end-to-end (requires root)
sudo go test -run 'TestFullFlow' -v ./...

# All tests (requires root)
sudo go test -v ./...
```

CI runs only Tier 1 tests, `go vet`, and build.

## Architecture

Four source files, single package `main`:

- **main.go** — Entry point, CLI flag parsing (slirp4netns-compatible), env config (`TS_AUTHKEY`, `TS_HOSTNAME`, `TS_EXIT_NODE`, `TS_CONTROL_URL`, `TS_STATE_DIR`), tsnet server lifecycle, ready/exit fd coordination with podman, signal handling.
- **ssh.go** — SSH server on the tsnet interface. Identifies peers via WhoIs, checks the allowlist (`TS_SSH_ALLOW`), discovers containers via pidfile scanning, and runs commands inside containers via `nsenter`.
- **netns.go** — Network namespace operations. `createTUNInNamespace()` uses a sacrificial goroutine pattern (LockOSThread + Setns, thread never returned) to create a TUN in the container's namespace. Interface configuration uses raw netlink/ioctl syscalls (no external dependencies).
- **tun.go** — `fdTUN` struct implementing the `tun.Device` interface, wrapping the file descriptor from namespace creation for use by tsnet.

### SSH container selection

The SSH username field selects which container to enter. `discoverContainers()` scans `dirname(TS_PIDFILE)` for `*.pid` files, reads each PID, and filters to those sharing the network namespace (via `validatePIDNetNS`). The SSH username must match a pidfile basename (without `.pid`).

**Single container:** `ssh nginx-demo@nginx-demo.tailnet` — the username `nginx-demo` matches `nginx-demo.pid` in the pidfile directory. There's only one container in the netns.

**Pod (multiple containers):** In a podman pod, all containers share a network namespace. Each container writes a pidfile to the same `%t` directory (e.g. `/run/user/<uid>/webapp-web.pid`, `/run/user/<uid>/webapp-api.pid`). The SSH username selects the target:
- `ssh webapp-web@webapp.tailnet` → enters the web container
- `ssh webapp-api@webapp.tailnet` → enters the api container
- `ssh wrong@webapp.tailnet` → error listing available containers

The allowlist (`TS_SSH_ALLOW`) maps tailnet identity to the OS user inside the container (e.g. `alice@example.com:root`). Container selection (SSH username) and OS user (allowlist) are independent.

### Key pattern: Sacrificial goroutine

Used in both TUN creation and interface configuration. A goroutine is locked to an OS thread, enters the container namespace via `Setns()`, performs work, and the thread is permanently discarded (no `UnlockOSThread()`). This prevents namespace contamination of the main goroutine.

### Testing infrastructure

Tests use `chanTUN` (channel-backed fake TUN) and `testcontrol` (fake Tailscale control server) from the Tailscale test libraries for integration tests without real network access or root.
