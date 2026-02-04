# ts4nsnet

A rootless container networking tool that acts as a drop-in replacement for
[slirp4netns](https://github.com/rootless-containers/slirp4netns). It creates a
TUN device inside a container's network namespace and bridges traffic onto the
tailnet via [tsnet](https://pkg.go.dev/tailscale.com/tsnet), making the
container appear as its own ephemeral Tailscale node.

## Requirements

- Linux (all source files are `//go:build linux`)
- Go 1.25+

## Usage

```sh
# Build
go build -o ts4nsnet .

# Run via podman
TS_AUTHKEY=tskey-auth-... TS_HOSTNAME=mycontainer \
  podman run --rm -it \
    --network-cmd-path=/path/to/ts4nsnet \
    --network slirp4netns \
    --dns=100.100.100.100 \
    --dns-search=MY_TAILNET_DOMAIN(e.g. tail12a34b).ts.net \
    alpine sh
```

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TS_AUTHKEY` | Yes | Tailscale auth key for the ephemeral node |
| `TS_HOSTNAME` | Yes | Hostname to register on the tailnet |
| `TS_EXIT_NODE` | No | IP address of an exit node to route traffic through |
| `TS_CONTROL_URL` | No | Custom control server URL |

## How it works

1. Podman invokes `ts4nsnet` as a slirp4netns replacement, passing the
   container's network namespace path and desired TUN device name.
2. `ts4nsnet` enters the container netns on a sacrificial goroutine, creates a
   raw TUN device (IFF_TUN | IFF_NO_PI), and sends the fd back.
3. A `tsnet.Server` is started with the TUN device, connecting to the Tailscale
   control plane using the provided auth key.
4. Once connected, the TUN interface is configured with the assigned tailnet IPs
   and default routes (using `ip` commands or raw netlink).
5. The container's traffic flows through the TUN into the tsnet engine, which
   handles WireGuard encryption and routing over the tailnet.

## Testing

```sh
# Unit tests (no root required)
go test -run 'TestResolveNSPath|TestParseEnvConfig|TestIgnoredFlags' -v ./...

# Integration tests with fake control server (no root required)
go test -run 'TestTsnetConnectsToControl|TestTwoNodesCanCommunicate|TestExitNodeConfig' -v ./...

# Namespace tests (requires root)
sudo go test -run 'TestCreateTUNInNamespace|TestConfigureInterface' -v ./...

# Full end-to-end (requires root)
sudo go test -run 'TestFullFlow' -v ./...
```

## TODO

- **Automatic MagicDNS search domain:** The tailnet's MagicDNS suffix (e.g.
  `tail38f29f.ts.net`) is available from the tsnet status after connecting, but
  there's currently no way to inject it into the container's `/etc/resolv.conf`
  as a search domain. Podman manages resolv.conf itself (via bind mount), and
  ts4nsnet only enters the network namespace, not the mount namespace. For now,
  users can pass `--dns-search=<tailnet-domain>` to podman if they know their
  domain. A proper solution likely requires coordination with the podman team to
  support a callback or protocol for the network command to communicate DNS
  search domains back to podman.

- **Rootless namespace tests:** Tier 3 and 4 tests (`TestCreateTUNInNamespace`,
  `TestConfigureInterface`, `TestFullFlow`) require root because they create
  network namespaces, TUN devices, and configure interfaces. These could run
  unprivileged by re-exec'ing the test binary under `unshare -Urnm` (user +
  network + mount namespaces) and mounting a tmpfs on `/run/netns/`. All the
  privileged operations (setns, TUN creation, netlink) are checked against the
  owning user namespace, so mapped-root is sufficient. For now, these tests
  follow the `os.Getuid() != 0 → t.Skip` pattern used throughout the Tailscale
  codebase.

## License

BSD 3-Clause — see [LICENSE](LICENSE).
