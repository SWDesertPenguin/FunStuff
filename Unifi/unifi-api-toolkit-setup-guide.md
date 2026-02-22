# UniFi API Toolkit — Setup & Usage Guide

## Prerequisites

**Machine requirements:**
- Linux/macOS/WSL (any machine on your Management VLAN)
- `curl` and `jq` installed
- Network access to your UDM-Pro management IP

**Install dependencies (if needed):**
```bash
# Debian/Ubuntu
sudo apt install curl jq

# macOS
brew install curl jq
```

## Quick Start

```bash
# 1. Make executable
chmod +x unifi-api-toolkit.sh

# 2. Run quick export (networks, firewall, devices)
./unifi-api-toolkit.sh quick

# 3. Run full export (everything)
./unifi-api-toolkit.sh all
```

You'll be prompted for your UDM IP and admin credentials. Credentials are never stored.

## What Gets Exported

| File | Contents | Sensitive? |
|------|----------|------------|
| `networks.json` | VLANs, subnets, DHCP config | Low — internal IPs only |
| `firewall_rules.json` | All firewall rules | Low — internal IPs only |
| `firewall_groups.json` | IP/port groups used in rules | Low |
| `devices.json` | UniFi hardware, firmware, IPs | Low |
| `active_clients.json` | Connected devices | Medium — MACs, hostnames |
| `known_clients.json` | All historical clients | Medium — MACs, hostnames |
| `wireless.json` | SSIDs, VLAN assignments | Low — **passwords auto-redacted** |
| `port_forwarding.json` | Port forward rules | Medium — shows exposed services |
| `port_profiles.json` | Switch port configurations | Low |
| `static_routes.json` | Routing table | Low |
| `traffic_rules.json` | QoS / traffic management | Low |
| `dns_records.json` | Local DNS entries | Low |
| `system_info.json` | Controller version, hostname | Low |
| `ips_settings.json` | IPS/IDS configuration | Low |
| `SUMMARY.md` | Human-readable overview | Low |

## Sharing with Claude — Priority Order

For most conversations, share these **in this order** (most useful first):

### Tier 1: Core Architecture (start here)
1. **`networks.json`** — VLAN structure, subnets, DHCP
2. **`firewall_rules.json`** + **`firewall_groups.json`** — Security policy
3. **`devices.json`** — Infrastructure inventory

### Tier 2: Context
4. **`active_clients.json`** — What's on the network now
5. **`wireless.json`** — WiFi config
6. **`port_forwarding.json`** — External exposure

### Tier 3: Specific Troubleshooting
7. Individual files as needed for the conversation topic

## Usage Examples

```bash
# Export just firewall rules
./unifi-api-toolkit.sh single firewall

# Export just client list
./unifi-api-toolkit.sh single clients

# Raw API query (outputs to stdout)
./unifi-api-toolkit.sh raw /proxy/network/api/s/default/stat/health

# Set UDM IP via environment variable
UDM_HOST=192.168.10.1 ./unifi-api-toolkit.sh quick

# Custom output directory
OUTPUT_DIR=~/Desktop/network-export ./unifi-api-toolkit.sh all
```

## Before Sharing: Security Checklist

Internal/RFC1918 IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x) are fine to share.

**Review and optionally redact:**
- [ ] Public/WAN IP addresses (if present)
- [ ] Real hostnames that reveal personal info
- [ ] MAC addresses (if privacy is a concern — usually fine for troubleshooting)
- [ ] Any custom DNS records pointing to external services

**Already handled by the script:**
- [x] WiFi passwords are auto-redacted
- [x] Admin credentials are never stored
- [x] Each file has metadata noting it should be reviewed

## Using Bearer Token (Alternative Auth)

If your UDM firmware supports API keys (UniFi OS 3.x+):

1. Go to: **Settings → Admins & Users → [Your Account] → API Access**
2. Generate a key
3. Set it as environment variable:

```bash
export UNIFI_API_KEY="your-key-here"
```

Then modify the script's `api_get` function to use:
```bash
curl -sk -H "Authorization: Bearer ${UNIFI_API_KEY}" "https://${UDM_HOST}${endpoint}"
```

This avoids interactive login — useful for cron jobs or scheduled exports.

## Automating Regular Exports

For maintaining up-to-date documentation, consider a weekly cron job:

```bash
# Add to crontab (crontab -e)
# Weekly export every Sunday at 3am
0 3 * * 0 UDM_HOST=192.168.10.1 /path/to/unifi-api-toolkit.sh all
```

> ⚠️ Requires non-interactive auth (Bearer token method above)

## Troubleshooting

**"Authentication failed"**
- Verify UDM IP is reachable: `ping 192.168.10.1`
- Ensure you're on the Management VLAN
- Try local admin account (not Ubiquiti cloud SSO)

**"Connection refused"**
- UDM uses HTTPS on port 443
- Verify: `curl -sk https://192.168.10.1`

**"jq: parse error"**
- API response may have changed in newer firmware
- Run with `raw` command to see actual response:
  `./unifi-api-toolkit.sh raw /proxy/network/api/s/default/rest/networkconf`

**Empty results**
- Some endpoints are firmware-version-dependent
- `traffic_rules` and `dns_records` may not exist on older firmware
