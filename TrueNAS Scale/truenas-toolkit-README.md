# TrueNAS Diagnostic Toolkit - Quick Reference

## Setup

### Option 1: Run Directly on TrueNAS (SSH)
```bash
# Copy script to TrueNAS
scp truenas-toolkit.sh admin@<TRUENAS_IP>:~/

# SSH in and make executable
ssh admin@<TRUENAS_IP>
chmod +x ~/truenas-toolkit.sh
```

### Option 2: Run Remotely (API)
```bash
# 1. Generate API key in TrueNAS UI:
#    Top-right user icon > API Keys > Add
#    Save the key somewhere safe (password manager)

# 2. Set environment variables (add to ~/.bashrc or ~/.zshrc):
export TRUENAS_HOST="192.168.10.X"    # Your TrueNAS management IP
export TRUENAS_API_KEY="your-key"      # API key from step 1

# 3. Run with --remote flag:
./truenas-toolkit.sh --remote diag
```

> ⚠️ **Security:** Store the API key in a secrets manager or env file, not in the script. The key has full admin access to your TrueNAS instance.

---

## Daily Use

### Quick Diagnostic (for Chat)
```bash
# Generate diagnostic, get prompted to save and sanitize
./truenas-toolkit.sh diag

# Or write directly to file (sanitization offered after)
./truenas-toolkit.sh -o diag.md diag

# Pipe to clipboard (skips sanitization — non-interactive)
./truenas-toolkit.sh diag 2>/dev/null | pbcopy        # macOS
./truenas-toolkit.sh diag 2>/dev/null | xclip -sel c  # Linux

# Remote:
./truenas-toolkit.sh --remote -o diag.md diag
```
Paste the output directly into our chat for troubleshooting.

### Update truenas_config.md
```bash
# Generate full config doc (prompted to save + sanitize)
./truenas-toolkit.sh full

# Write to specific file
./truenas-toolkit.sh -o truenas_config.md full

# Skip sanitization prompt (for automation/cron)
./truenas-toolkit.sh --no-sanitize -o truenas_config.md full

# Remote:
./truenas-toolkit.sh --remote -o truenas_config.md full
```

### Targeted Diagnostics
```bash
# When I ask "what's your pool status?"
./truenas-toolkit.sh pools

# When I ask "check your disk health"
./truenas-toolkit.sh disks
./truenas-toolkit.sh smart

# When I ask "what services are running?"
./truenas-toolkit.sh services

# When I ask "any alerts?"
./truenas-toolkit.sh alerts

# When I ask "what's your share config?"
./truenas-toolkit.sh shares

# When I ask "what apps are running?"
./truenas-toolkit.sh apps

# When I ask "check your network config"
./truenas-toolkit.sh network
```

> **Note:** Targeted commands (`pools`, `disks`, etc.) output to stdout without a sanitization prompt. To sanitize targeted output, write to a file first and then run `sanitize`:
> ```bash
> ./truenas-toolkit.sh network > network_info.md
> ./truenas-toolkit.sh sanitize network_info.md
> ```

---

## Data Sanitization

The toolkit includes interactive sanitization for safely sharing configs in chats, forums, or documentation without exposing sensitive data.

### How Sanitization Works

Sanitization is offered automatically after `full` or `diag` commands write to a file. You can also run it standalone on any existing markdown file.

**Three ways to trigger it:**

```bash
# 1. Auto-prompt: runs after full/diag when writing to file
./truenas-toolkit.sh -o truenas_config.md full
# → generates file → sanitization menu appears

# 2. Auto-prompt: full/diag in interactive terminal (no -o flag)
./truenas-toolkit.sh full
# → asks for filename → generates → sanitization menu appears

# 3. Standalone: sanitize any existing file
./truenas-toolkit.sh sanitize truenas_config.md
./truenas-toolkit.sh sanitize my_diag_output.md
```

### Sanitization Menu

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Sanitization Options
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  File: truenas_config.md

  1) Disk serial numbers
  2) Public (WAN) IP addresses only
  3) All IP addresses (public + private)
  4) MAC addresses (preserves vendor prefix)
  5) Hostname
  6) Share/dataset paths
  7) Pool/dataset names (you type them)
  8) Usernames (you type them)
  9) Custom strings (you type them)

  A) All automatic (1-6)
  F) Full sanitize (1-9, prompts for 7-9)
  S) Skip — keep file as-is

  Enter choices (e.g. 1,2,4 or A or F or S) >
```

### Sanitization Options Explained

| Option | What It Redacts | Example |
|--------|----------------|---------|
| **1 - Serials** | Disk serial numbers | `WDC12345678` → `SERIAL-REDACTED-001` |
| **2 - Public IPs** | WAN/public IPs only (keeps private) | `70.175.x.x` → `WAN-IP-REDACTED-001` |
| **3 - All IPs** | Public + private (RFC1918) IPs | `192.168.10.5` → `PRIV-IP-REDACTED-001` |
| **4 - MACs** | MAC addresses (keeps OUI vendor prefix) | `6c:63:f8:a9:bb:20` → `6c:63:f8:XX:XX:01` |
| **5 - Hostname** | System hostname | `truenas.local` → `HOSTNAME-REDACTED` |
| **6 - Paths** | Share and dataset paths (`/mnt/...`) | `/mnt/tank/media` → `/mnt/POOL-REDACTED/share-001` |
| **7 - Pool names** | Pool/dataset names you specify | (interactive prompt) |
| **8 - Usernames** | Usernames you specify | (interactive prompt) |
| **9 - Custom** | Any arbitrary strings you specify | (interactive prompt) |
| **A - Auto** | All automatic options (1-6) | No prompts needed |
| **F - Full** | Everything (1-9) | Prompts for 7-9 |

### Shortcuts

| Shortcut | Selects | Best For |
|----------|---------|----------|
| `A` | Options 1-6 | Quick share for chat — redacts all detectable sensitive data |
| `F` | Options 1-9 | Forum posts or public sharing — full scrub including custom items |
| `1,2` | Just serials + public IPs | Sharing with trusted people (keeps internal topology visible) |
| `2` | Public IPs only | Minimal redaction — just hide your WAN IP |
| `S` | Nothing | Keep raw output (for private docs / git repo) |

### Safety Features

- **Backup created automatically** — original saved as `filename.bak` before any changes
- **Redaction log** (optional) — maps `SERIAL-REDACTED-001` back to originals so you can decode later
  - Saved as `filename-redaction-log.txt`
  - ⚠️ Keep this file private — it contains your original sensitive data
- **Non-interactive safe** — piped output and `--no-sanitize` skip the prompt automatically
- **OUI prefix preserved** on MACs — you can still identify device vendors (Ubiquiti, etc.)

### Restore Original
```bash
# Backup is always saved as .bak
mv truenas_config.md.bak truenas_config.md

# Or delete the backup when you're done
rm truenas_config.md.bak
```

### Typical Sanitization Workflows

**Sharing in chat (quick):**
```bash
./truenas-toolkit.sh -o diag.md diag
# Select: A (all automatic)
# Paste diag.md contents into chat
```

**Posting on a forum:**
```bash
./truenas-toolkit.sh -o truenas_config.md full
# Select: F (full sanitize)
# Enter pool names, usernames, any custom strings when prompted
# Save redaction log: y (so you can decode responses)
```

**Private docs (no sanitization):**
```bash
./truenas-toolkit.sh --no-sanitize -o truenas_config.md full
```

**Re-sanitize a file you already generated:**
```bash
./truenas-toolkit.sh sanitize truenas_config.md
```

---

## Command Cheat Sheet

| Command | What It Pulls | When to Use |
|---------|--------------|-------------|
| `diag` | System + alerts + pools + services + apps | Start of troubleshooting session |
| `full` | Everything → markdown doc | Monthly refresh or after major changes |
| `sanitize` | Redact sensitive data from existing file | Before sharing configs |
| `system` | CPU, RAM, uptime, version | Performance questions |
| `pools` | Pool health + dataset usage | Storage issues |
| `disks` | Disk inventory + temps | Hardware health check |
| `smart` | SMART test results per disk | Disk failure investigation |
| `network` | Interfaces, IPs, routes | Connectivity issues |
| `services` | All services + state | Service not responding |
| `shares` | SMB + NFS + iSCSI config | Share access problems |
| `apps` | App/container status | App not working |
| `vms` | VM config + devices | VM issues |
| `alerts` | Active alerts | Any time something seems wrong |
| `updates` | Available updates | Before maintenance window |
| `replication` | Replication task status | Backup verification |
| `snapshots` | Snapshot tasks + counts | Storage cleanup |
| `cron` | Scheduled tasks | Automation review |
| `boot` | Boot pool health | Boot issues |

## Flags

| Flag | Description |
|------|-------------|
| `--remote`, `-r` | Use REST API instead of local `midclt` |
| `--host IP` | TrueNAS hostname/IP (default: `$TRUENAS_HOST`) |
| `--api-key KEY` | API key (default: `$TRUENAS_API_KEY`) |
| `-o`, `--output FILE` | Write output to file instead of stdout |
| `--md-file FILE` | Filename for full markdown (default: `truenas_config.md`) |
| `--no-sanitize` | Skip the sanitization prompt |

---

## Workflow for Chat Sessions

### Starting a New Troubleshooting Session
```bash
# Pull quick diagnostic and sanitize for sharing
./truenas-toolkit.sh -o /tmp/diag.md diag
# Select: A (all automatic)
# Paste /tmp/diag.md into chat
```

### After Making Changes
```bash
# 1. Pull the relevant section to verify
./truenas-toolkit.sh pools        # if you changed storage
./truenas-toolkit.sh network      # if you changed networking
./truenas-toolkit.sh services     # if you changed services
./truenas-toolkit.sh shares       # if you changed shares

# 2. Refresh the full config doc (unsanitized for your private repo)
./truenas-toolkit.sh --no-sanitize -o truenas_config.md full

# 3. Commit to git
cd ~/docs && git add truenas_config.md && git commit -m "Updated after [change]"
```

### Monthly Maintenance
```bash
# Full refresh of documentation
./truenas-toolkit.sh --no-sanitize -o truenas_config.md full

# Check for issues
./truenas-toolkit.sh alerts
./truenas-toolkit.sh smart
./truenas-toolkit.sh updates
```

---

## Dependencies

- **jq** - JSON parser (should be pre-installed on TrueNAS Scale)
  ```bash
  # If missing:
  apt install jq  # on TrueNAS (as root)
  ```
- **midclt** - TrueNAS middleware client (built-in, local mode only)
- **curl** - HTTP client (for remote API mode, usually pre-installed)
- **numfmt** - Number formatting (part of coreutils, pre-installed)

## Troubleshooting the Toolkit

| Problem | Solution |
|---------|----------|
| `midclt not found` | You're not on TrueNAS. Use `--remote` mode |
| `API key not set` | Set `TRUENAS_API_KEY` env variable |
| `Connection refused` | Check TrueNAS IP, ensure API service is running |
| `Permission denied` | API key may have expired. Regenerate in TrueNAS UI |
| `jq: command not found` | Install jq: `apt install jq` |
| Empty/N/A output | Some APIs changed between TrueNAS versions. Check your version |
| `syntax error: invalid arithmetic operator` | Float from API — update script (fixed in current version) |
| Sanitization menu doesn't appear | Only shows in interactive terminal. Piped output skips it. Use `sanitize` command instead |

---

## File Output Summary

| File | Purpose | Sensitive? |
|------|---------|------------|
| `truenas_config.md` | Full config documentation | ✅ Yes — sanitize before sharing |
| `truenas_config.md.bak` | Pre-sanitization backup | ✅ Yes — contains originals |
| `truenas_config-redaction-log.txt` | Maps redacted → original values | ✅ Yes — keep private |
| `truenas_diag_YYYYMMDD_HHMMSS.md` | Quick diagnostic snapshot | ✅ Yes — sanitize before sharing |

---

## Version Control Recommendation

Keep your documentation in git:

```bash
mkdir -p ~/network-docs && cd ~/network-docs
git init

# Add your docs
cp ~/truenas_config.md .
# ... add other network docs ...

git add -A
git commit -m "Initial network documentation"

# After each toolkit run (unsanitized for private repo):
./truenas-toolkit.sh --no-sanitize -o truenas_config.md full
git add truenas_config.md
git commit -m "TrueNAS config refresh $(date +%Y-%m-%d)"
```

This gives you a full change history of your TrueNAS configuration over time.

> **Tip:** Never commit `.bak` or redaction log files to your repo. Add them to `.gitignore`:
> ```
> *.bak
> *-redaction-log.txt
> ```
