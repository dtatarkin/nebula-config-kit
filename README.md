# nebula-config-kit

**Stop hand-crafting Nebula configs. Define your mesh network once, generate configs for every host.**

nebula-config-kit is a Python library and CLI for managing [Nebula](https://github.com/slackhq/nebula) overlay network configurations. It takes a single declarative YAML file describing your entire network — hosts, lighthouses, relays, firewall rules — and generates validated, ready-to-deploy Nebula configs for each node.

---

## Why?

Managing a Nebula mesh network means juggling per-host YAML files that share 90% of their content but differ in subtle, error-prone ways. nebula-config-kit solves this:

- **Single source of truth** — one config file defines your entire network topology
- **Type-safe validation** — Pydantic models catch misconfigurations before deployment (duplicate IPs, missing lighthouses, invalid rules)
- **Automatic resolution** — lighthouse maps, relay lists, and firewall rules are computed per-host from your network definition
- **PKI integration** — built-in certificate management via pki-kit (CA creation, host cert signing, revocation)
- **Comment-preserving templates** — generated configs retain the original Nebula YAML comments for readability

## Quick start

### Install

```bash
# With CLI
pip install nebula-config-kit[cli]

# Library only
pip install nebula-config-kit
```

### Define your network

Create `nebula-network.config.yml`:

```yaml
network:
  cidr: 10.10.0.0/16

certs:
  ca_name: "My Network CA"
  ca_duration: 3650d
  host_duration: 365d

hosts:
  defaults:
    listen_port: 4242
    tun_dev: nebula1
  hosts:
    lighthouse1:
      nebula_ip: 10.10.0.1
      public_endpoints: ["203.0.113.10"]
    webserver:
      nebula_ip: 10.10.0.10
    database:
      nebula_ip: 10.10.0.20

firewall:
  security_groups:
    icmp:
      port: any
      proto: icmp
      direction: any
    ssh:
      port: 22
      proto: tcp
      direction: in
    https:
      port: 443
      proto: tcp
      direction: in
  firewall_default:
    all: [icmp]
  firewall_rules:
    webserver:
      all: [ssh, https]
    database:
      webserver: [ssh]
```

### Generate configs

```bash
# List all hosts
nebula-config hosts list

# Show resolved details for a host
nebula-config hosts show webserver

# Generate a complete Nebula config
nebula-config config generate webserver -o webserver.yml
```

### Use as a library

```python
from pathlib import Path
from nebula_config_kit import load_config, resolve_host, generate_host_config
from nebula_config_kit.types import HostName

config = load_config(path=Path("nebula-network.config.yml"))
host = resolve_host(name=HostName("webserver"), config=config)
```

## Features

### Host resolution

Hosts inherit from `defaults` and can override any setting. Lighthouses are auto-detected from hosts with `public_endpoints`. Relays are identified by the `am_relay` flag. Each host gets a resolved config with the correct static host map, lighthouse list, and relay list — excluding itself.

### Security groups & firewall

Define reusable security groups, assign them to hosts or host groups, and nebula-config-kit resolves the full inbound/outbound firewall ruleset per host. Default rules apply to all hosts unless overridden.

### PKI management

Integrated certificate lifecycle:

- CA key and certificate generation
- Host certificate signing with correct Nebula IP and groups
- Certificate revocation
- Validity tracking and renewal hints
- SOPS-encrypted key storage support

### CLI output formats

```bash
# Table (default), JSON, or YAML
nebula-config hosts list --output json
nebula-config hosts show database --output yaml
```

### Custom templates

Override the built-in Nebula config template to include your own settings:

```bash
nebula-config config generate webserver --template my-template.yml
```

## Configuration

| Environment Variable              | Default                     | Description                                |
| --------------------------------- | --------------------------- | ------------------------------------------ |
| `NEBULA_NETWORK_CONFIG`           | `nebula-network.config.yml` | Path to network config file                |
| `NEBULA_CONFIG_KIT_PKI_PATH`      | `.`                         | Root directory for PKI stores              |
| `NEBULA_CONFIG_KIT_PKI_NAME`      | `default`                   | PKI instance name                          |
| `NEBULA_CONFIG_KIT_SOPS_ARGS`     | —                           | Extra SOPS arguments for encrypted keys    |
| `NEBULA_CONFIG_KIT_OUTPUT_FORMAT` | `table`                     | CLI output format: `table`, `json`, `yaml` |

## Development

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
# Install dependencies
uv sync --all-extras

# Run tests
just test

# Lint + type check
just lint

# All checks
just check
```

## License

See [LICENSE](LICENSE) for details.
