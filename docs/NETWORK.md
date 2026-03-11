# OAIE Network Control

OAIE provides three network modes that control outbound connectivity for
sandboxed processes. The default is complete network isolation. When selective
access is needed, the allowlist mode creates an isolated network namespace
with nftables filtering, a veth pair for connectivity, and a DNS proxy for
domain-based filtering.

## Network Modes

| Mode | Namespace | Connectivity | Filtering | Use case |
|---|---|---|---|---|
| **Off** (default) | `CLONE_NEWNET` | None | n/a | Untrusted tools, no network needed |
| **On** | Host network | Full | None | Trusted tools needing unrestricted access |
| **Allowlist** | `CLONE_NEWNET` + veth | Filtered | nftables + DNS proxy | API calls to specific endpoints |

## CLI Usage

### Basic Syntax

```bash
# No network (default)
oaie run -- ./tool

# Full host network
oaie run --net=on -- curl https://example.com

# Allowlist a single endpoint
oaie run --net='allow:api.anthropic.com:443' -- ./llm_client

# Allowlist multiple endpoints
oaie run --net='allow:api.anthropic.com:443,api.openai.com:443' -- ./multi_llm

# Allowlist with CIDR and protocol
oaie run --net='allow:10.0.0.0/24:8080/tcp' -- ./internal_client

# Use a named preset
oaie run --net='preset:anthropic' -- ./claude_agent
oaie run --net='preset:llm' -- ./multi_provider_agent
```

### Network Presets

| Preset | Allowed endpoints |
|---|---|
| `anthropic` | `api.anthropic.com:443/tcp` |
| `openai` | `api.openai.com:443/tcp` |
| `llm` | `api.anthropic.com:443/tcp`, `api.openai.com:443/tcp`, `generativelanguage.googleapis.com:443/tcp` |

### TOML Policy Syntax

```toml
[defaults]
network = false          # Off (boolean shorthand)
network = true           # On (boolean shorthand)

[defaults.network]       # Allowlist (table form)
mode = "allowlist"

[[defaults.network.allow]]
host = "api.anthropic.com"
port = 443
protocol = "tcp"

[[defaults.network.allow]]
cidr = "10.0.0.0/16"
port = 8080
protocol = "tcp"
```

## AllowRule Structure

Each allowlist rule specifies a single permitted network endpoint.

| Field | Type | Required | Description |
|---|---|---|---|
| `host` | string | one of host/cidr | DNS hostname (resolved before sandbox starts) |
| `cidr` | string | one of host/cidr | IP range in CIDR notation |
| `port` | u16 | yes | Destination port (must be > 0) |
| `protocol` | string | no (default: tcp) | Transport protocol: `tcp` or `udp` |

`host` and `cidr` are mutually exclusive. Specify one per rule, never both.
When `host` is used, DNS resolution happens on the host before the sandbox
starts. All resolved IP addresses become nftables accept rules.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Host Network Namespace                                      │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ OAIE        │  │ DNS Proxy    │  │ nftables (host)    │  │
│  │ Supervisor  │  │ 127.0.0.53   │  │ MASQUERADE + FWD   │  │
│  └──────┬──────┘  └──────┬───────┘  └────────────────────┘  │
│         │                │                                   │
│         │          ┌─────┴─────┐                             │
│         │          │ veth-host │                              │
│         │          └─────┬─────┘                             │
│─────────│────────────────│───────────────────────────────────│
│         │          ┌─────┴─────┐                             │
│         │          │ veth-ns   │                              │
│         │          └─────┬─────┘                             │
│  Sandbox Network Namespace                                   │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ Tool        │  │ resolv.conf  │  │ nftables (ns)      │  │
│  │ Process     │  │ →127.0.0.53  │  │ output: DROP       │  │
│  │             │  │              │  │ + allow rules       │  │
│  └─────────────┘  └──────────────┘  └────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Setup Sequence

1. **DNS pre-resolution**: All `host` rules are resolved to IP addresses on
   the host before the sandbox starts. This happens outside the sandbox to
   prevent DNS-based sandbox escape.

2. **Namespace creation**: `CLONE_NEWNET` creates an isolated network namespace.

3. **veth pair**: A virtual ethernet pair connects the sandbox namespace to the
   host. The host-side interface gets NAT (MASQUERADE) and IP forwarding.

4. **nftables rules**: Applied inside the sandbox namespace via `nsenter`.
   Default policy is DROP on the output chain. Explicit ACCEPT rules are
   added for each resolved IP:port/protocol combination.

5. **DNS proxy**: A thread on the host listens on 127.0.0.53:53 inside the
   sandbox namespace. It filters DNS queries against the allowlist domains
   and forwards permitted queries to the real upstream resolver.

6. **resolv.conf injection**: The sandbox's `/etc/resolv.conf` points to
   `127.0.0.53` so all DNS goes through the filtering proxy.

## nftables Details

The generated nft batch script creates an `inet oaie_filter` table:

```
add table inet oaie_filter
add chain inet oaie_filter output { type filter hook output priority 0; policy drop; }
add rule inet oaie_filter output ct state established,related accept
add rule inet oaie_filter output oifname "lo" accept
add rule inet oaie_filter output ip daddr 104.18.32.7 tcp dport 443 counter accept
add rule inet oaie_filter output ip daddr 104.18.33.7 tcp dport 443 counter accept
add rule inet oaie_filter output ip daddr 127.0.0.53 udp dport 53 accept
add rule inet oaie_filter output ip daddr 127.0.0.53 tcp dport 53 accept
```

Key nftables features used:

- **Stateful tracking** (`ct state established,related`): Return traffic for
  allowed connections passes without explicit rules.
- **Byte counters** (`counter`): Each accept rule tracks bytes for the
  `max_network_bytes` budget enforcement.
- **Loopback passthrough**: All loopback traffic is accepted (needed for the
  DNS proxy on 127.0.0.53).

Rules are applied via `nsenter --net=/proc/<pid>/ns/net nft -f -` with the
script piped to stdin. The `nsenter` approach avoids needing root access or
capabilities on the host.

## DNS Proxy

The DNS proxy is a lightweight thread that:

1. Binds to 127.0.0.53:53 (UDP) inside the sandbox namespace.
2. Receives DNS queries from the sandboxed process.
3. Extracts the queried domain from the DNS wire format.
4. Checks the domain against the allowlist (exact match and pattern matching).
5. Forwards permitted queries to the real upstream resolver.
6. Returns SERVFAIL for denied queries and upstream failures.
7. Verifies transaction IDs to prevent spoofing.

DNS event recording is bounded at 10,000 events per run to prevent memory
exhaustion from DNS flooding attacks.

## TLS SNI Extraction

For additional visibility, the network policy module can extract the Server
Name Indication (SNI) from TLS ClientHello messages. This provides a
second-layer domain verification beyond DNS, as a compromised DNS response
cannot change the SNI that the client sends.

## Per-Tool Network Denial

In session mode, specific tools can be denied network access regardless of
the session's overall network configuration:

```bash
oaie session run --deny-net-tools='curl,wget,nc' --contained=cloud -- ./agent
```

Glob patterns match on the command basename. When a denied tool is dispatched,
its sandbox gets `NetworkMode::Off` even if the session allows network access.

## Byte Counting

When `max_network_bytes` is set in the session budget, OAIE reads the nftables
byte counters after each tool call to track cumulative network usage. At 80%
of the limit, a `BudgetWarning` event is emitted. When the limit is reached,
further tool calls that require network access are rejected.

```bash
oaie session run --budget-network-bytes=100M --contained=cloud -- ./agent
```

## Doctor Probes

Three doctor probes validate network policy prerequisites:

| Probe | Check | Remediation |
|---|---|---|
| **#17** | `nft` binary available | Install nftables package |
| **#18** | IP forwarding enabled (`/proc/sys/net/ipv4/ip_forward`) | `sysctl net.ipv4.ip_forward=1` |
| **#19** | `nsenter` binary available | Install util-linux package |

Run `oaie doctor` to check all prerequisites including network policy support.
