#!/usr/bin/env bash
# ============================================================================
# TrueNAS Diagnostic Toolkit
# Purpose: Pull system diagnostics for chat troubleshooting & generate/update
#          the truenas_config.md documentation file.
#
# Usage:
#   LOCAL  (SSH into TrueNAS):  ./truenas-toolkit.sh <command>
#   REMOTE (from mgmt VLAN):    ./truenas-toolkit.sh --remote <command>
#
# Commands:
#   full        - Generate complete truenas_config.md
#   diag        - Quick diagnostic summary (paste into chat)
#   sanitize    - Sanitize an existing file (redact sensitive data)
#   system      - System info (CPU, RAM, OS, uptime)
#   pools       - Pool status and dataset usage
#   disks       - Disk inventory and SMART health
#   smart       - Detailed SMART data for all disks
#   network     - Network interfaces and configuration
#   services    - Service status
#   shares      - SMB and NFS share configuration
#   apps        - Installed apps/containers
#   vms         - Virtual machines
#   alerts      - Current system alerts
#   updates     - Available system updates
#   replication - Replication task status
#   snapshots   - Snapshot summary
#   cron        - Cron/periodic task configuration
#   boot        - Boot pool status
#   help        - Show this help
#
# Configuration:
#   For remote mode, set these environment variables or edit below:
#     TRUENAS_HOST=192.168.10.X
#     TRUENAS_API_KEY=your-api-key-here
#
# Output:
#   All output is Markdown-formatted for direct use in documentation
#   or pasting into chat conversations.
# ============================================================================

set -uo pipefail
# Note: intentionally NOT using set -e so the script continues if one module fails

# ── Configuration ───────────────────────────────────────────────────────────
TRUENAS_HOST="${TRUENAS_HOST:-192.168.10.X}"       # Change to your TrueNAS IP
TRUENAS_API_KEY="${TRUENAS_API_KEY:-}"               # Set via env or edit here
REMOTE_MODE=false
OUTPUT_FILE=""
MD_FILE="truenas_config.md"

# ── Color / formatting (disabled if piping) ─────────────────────────────────
if [[ -t 1 ]]; then
  BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
  GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; CYAN='\033[36m'
else
  BOLD=''; DIM=''; RESET=''; GREEN=''; YELLOW=''; RED=''; CYAN=''
fi

# ── Helpers ─────────────────────────────────────────────────────────────────

usage() {
  grep -A 100 '^# Commands:' "$0" | grep -B 100 '^# Configuration:' | grep '^#' | sed 's/^# *//'
  exit 0
}

err() { echo -e "${RED}ERROR: $*${RESET}" >&2; }
info() { echo -e "${DIM}>> $*${RESET}" >&2; }

# Unified query function - works local (midclt) or remote (API)
query() {
  local endpoint="$1"
  shift
  local params="${*:-}"

  if $REMOTE_MODE; then
    # Remote: REST API via curl
    if [[ -z "$TRUENAS_API_KEY" ]]; then
      err "TRUENAS_API_KEY not set. Generate one in TrueNAS UI: Top-right user menu > API Keys"
      exit 1
    fi
    local url="https://${TRUENAS_HOST}/api/v2.0/${endpoint}"
    if [[ -n "$params" ]]; then
      curl -sk -H "Authorization: Bearer ${TRUENAS_API_KEY}" \
        -H "Content-Type: application/json" \
        -X POST "$url" \
        -d "$params" 2>/dev/null
    else
      curl -sk -H "Authorization: Bearer ${TRUENAS_API_KEY}" \
        "$url" 2>/dev/null
    fi
  else
    # Local: midclt
    if ! command -v midclt &>/dev/null; then
      err "midclt not found. Are you running this on TrueNAS? Use --remote for API mode."
      exit 1
    fi
    if [[ -n "$params" ]]; then
      midclt call "$endpoint" "$params" 2>/dev/null
    else
      midclt call "$endpoint" 2>/dev/null
    fi
  fi
}

# Safe jq wrapper - returns "N/A" on failure
jq_safe() {
  jq -r "$@" 2>/dev/null || echo "N/A"
}

# Format bytes to human readable
human_bytes() {
  local bytes="${1:-0}"
  if [[ "$bytes" == "null" || "$bytes" == "N/A" || -z "$bytes" ]]; then
    echo "N/A"
    return
  fi
  # Truncate any decimal (bash/numfmt can't handle floats)
  bytes=${bytes%%.*}
  numfmt --to=iec-i --suffix=B "$bytes" 2>/dev/null || echo "${bytes} bytes"
}

# Section header for markdown output
md_section() {
  local level="${1:-2}"
  local title="$2"
  local hashes
  hashes=$(printf '#%.0s' $(seq 1 "$level"))
  echo ""
  echo "$hashes $title"
  echo ""
}

# Timestamp
now() {
  date '+%Y-%m-%d %H:%M:%S %Z'
}

# ── Diagnostic Modules ──────────────────────────────────────────────────────

collect_system() {
  info "Collecting system info..."
  local data
  data=$(query "system.info")

  local hostname version uptime_sec loadavg timezone
  hostname=$(echo "$data" | jq_safe '.hostname')
  version=$(echo "$data" | jq_safe '.version')
  uptime_sec=$(echo "$data" | jq_safe '.uptime_seconds')
  loadavg=$(echo "$data" | jq_safe '.loadavg | map(tostring) | join(", ")')
  timezone=$(echo "$data" | jq_safe '.timezone')

  # CPU and memory
  local cores model
  cores=$(echo "$data" | jq_safe '.cores')
  model=$(echo "$data" | jq_safe '.model // "N/A"')

  local physmem
  physmem=$(echo "$data" | jq_safe '.physmem')
  local physmem_human
  physmem_human=$(human_bytes "$physmem")

  # Calculate uptime as days/hours (truncate float to int)
  local uptime_human="N/A"
  if [[ "$uptime_sec" != "N/A" && "$uptime_sec" != "null" ]]; then
    local uptime_int=${uptime_sec%%.*}
    local days=$((uptime_int / 86400))
    local hours=$(( (uptime_int % 86400) / 3600 ))
    uptime_human="${days}d ${hours}h"
  fi

  md_section 2 "System Information"
  echo "| Property | Value |"
  echo "|----------|-------|"
  echo "| **Hostname** | $hostname |"
  echo "| **TrueNAS Version** | $version |"
  echo "| **Uptime** | $uptime_human |"
  echo "| **CPU** | $model |"
  echo "| **CPU Cores** | $cores |"
  echo "| **Total RAM** | $physmem_human |"
  echo "| **Load Average** | $loadavg |"
  echo "| **Timezone** | $timezone |"

  # Advanced config
  local adv
  adv=$(query "system.advanced.config" 2>/dev/null || echo "{}")
  local serial_console consolemenu
  serial_console=$(echo "$adv" | jq_safe '.serialconsole')
  consolemenu=$(echo "$adv" | jq_safe '.consolemenu')

  echo ""
  echo "**Advanced Settings:**"
  echo "- Serial Console: $serial_console"
  echo "- Console Menu: $consolemenu"
}

collect_pools() {
  info "Collecting pool information..."
  local pools
  pools=$(query "pool.query")

  md_section 2 "Storage Pools"

  echo "$pools" | jq -c '.[]' 2>/dev/null | while read -r pool; do
    local name status path healthy
    name=$(echo "$pool" | jq_safe '.name')
    status=$(echo "$pool" | jq_safe '.status')
    path=$(echo "$pool" | jq_safe '.path')
    healthy=$(echo "$pool" | jq_safe '.healthy')

    local scan_state scan_errors
    scan_state=$(echo "$pool" | jq_safe '.scan.state // "N/A"')
    scan_errors=$(echo "$pool" | jq_safe '.scan.errors // 0')

    echo "### Pool: $name"
    echo ""
    echo "| Property | Value |"
    echo "|----------|-------|"
    echo "| **Status** | $status |"
    echo "| **Healthy** | $healthy |"
    echo "| **Path** | $path |"
    echo "| **Last Scan State** | $scan_state |"
    echo "| **Scan Errors** | $scan_errors |"
    echo ""

    # Topology (vdevs)
    echo "**Topology:**"
    echo ""
    echo '```'
    echo "$pool" | jq -r '
      .topology | to_entries[] |
      "\(.key):" as $type |
      .value[] |
      "  \($type) \(.type // "N/A") - status: \(.status // "N/A")" as $vdev |
      $vdev,
      (.children[]? |
        "    └─ \(.disk // .path // "unknown") [\(.status // "N/A")]"
      )
    ' 2>/dev/null || echo "  (unable to parse topology)"
    echo '```'
    echo ""
  done

  # Dataset usage
  info "Collecting dataset usage..."
  local datasets
  datasets=$(query "pool.dataset.query")

  echo "### Dataset Usage"
  echo ""
  echo "| Dataset | Used | Available | Compression | Quota |"
  echo "|---------|------|-----------|-------------|-------|"

  echo "$datasets" | jq -c '.[]' 2>/dev/null | while read -r ds; do
    local dsname used avail compress quota
    dsname=$(echo "$ds" | jq_safe '.name')
    used=$(echo "$ds" | jq_safe '.used.parsed // .used.rawvalue // "N/A"')
    avail=$(echo "$ds" | jq_safe '.available.parsed // .available.rawvalue // "N/A"')
    compress=$(echo "$ds" | jq_safe '.compression.value // "N/A"')
    quota=$(echo "$ds" | jq_safe '.quota.parsed // .quota.rawvalue // "N/A"')
    echo "| $dsname | $used | $avail | $compress | $quota |"
  done
  echo ""
}

collect_disks() {
  info "Collecting disk information..."
  local disks
  disks=$(query "disk.query")

  md_section 2 "Disk Inventory"

  echo "| Device | Serial | Model | Size | Type | Pool | Temp | SMART |"
  echo "|--------|--------|-------|------|------|------|------|-------|"

  echo "$disks" | jq -c '.[]' 2>/dev/null | while read -r disk; do
    local dev serial model size dtype pool temp smart_ok
    dev=$(echo "$disk" | jq_safe '.devname // .name')
    serial=$(echo "$disk" | jq_safe '.serial')
    model=$(echo "$disk" | jq_safe '.model')
    size=$(echo "$disk" | jq_safe '.size')
    dtype=$(echo "$disk" | jq_safe '.type')
    pool=$(echo "$disk" | jq_safe '.pool // "unassigned"')

    # Temperature (may be null)
    temp=$(echo "$disk" | jq_safe '.temperature // "N/A"')
    if [[ "$temp" != "N/A" && "$temp" != "null" ]]; then
      temp="${temp}°C"
    fi

    # SMART status
    smart_ok=$(echo "$disk" | jq_safe '.smart_enabled // false')

    local size_human
    size_human=$(human_bytes "$size")

    echo "| $dev | $serial | $model | $size_human | $dtype | $pool | $temp | $smart_ok |"
  done
  echo ""
}

collect_smart() {
  info "Collecting SMART data..."
  local disks
  disks=$(query "disk.query")

  md_section 2 "SMART Health Details"

  echo "$disks" | jq -r '.[].identifier' 2>/dev/null | while read -r ident; do
    if [[ -z "$ident" || "$ident" == "null" ]]; then continue; fi
    local devname
    devname=$(echo "$disks" | jq -r ".[] | select(.identifier == \"$ident\") | .devname // .name" 2>/dev/null)

    echo "### $devname ($ident)"
    echo ""

    # Try to get SMART test results
    local results
    results=$(query "smart.test.results" "[\"$ident\"]" 2>/dev/null || echo "[]")

    if [[ "$results" == "[]" || "$results" == "null" || -z "$results" ]]; then
      echo "_No SMART test results available._"
    else
      echo "| Test | Status | Remaining | Lifetime Hours | LBA |"
      echo "|------|--------|-----------|----------------|-----|"
      echo "$results" | jq -c '.[]' 2>/dev/null | head -5 | while read -r test; do
        local ttype tstatus tremain thours tlba
        ttype=$(echo "$test" | jq_safe '.description // .type // "N/A"')
        tstatus=$(echo "$test" | jq_safe '.status // "N/A"')
        tremain=$(echo "$test" | jq_safe '.remaining // "N/A"')
        thours=$(echo "$test" | jq_safe '.lifetime // "N/A"')
        tlba=$(echo "$test" | jq_safe '.lba_of_first_error // "none"')
        echo "| $ttype | $tstatus | $tremain | $thours | $tlba |"
      done
    fi
    echo ""
  done
}

collect_network() {
  info "Collecting network configuration..."
  local config interfaces
  config=$(query "network.configuration" 2>/dev/null || echo "{}")
  interfaces=$(query "interface.query" 2>/dev/null || echo "[]")

  md_section 2 "Network Configuration"

  local hn domain nameservers gateway gateway6
  hn=$(echo "$config" | jq_safe '.hostname')
  domain=$(echo "$config" | jq_safe '.domain')
  nameservers=$(echo "$config" | jq_safe '.nameserver1, .nameserver2, .nameserver3' | grep -v null | tr '\n' ', ' | sed 's/,$//')
  gateway=$(echo "$config" | jq_safe '.ipv4gateway')
  gateway6=$(echo "$config" | jq_safe '.ipv6gateway // "N/A"')

  echo "| Property | Value |"
  echo "|----------|-------|"
  echo "| **Hostname** | $hn |"
  echo "| **Domain** | $domain |"
  echo "| **DNS Servers** | $nameservers |"
  echo "| **IPv4 Gateway** | $gateway |"
  echo "| **IPv6 Gateway** | $gateway6 |"
  echo ""

  echo "### Interfaces"
  echo ""
  echo "| Interface | Type | State | IP Address(es) | MTU | VLAN |"
  echo "|-----------|------|-------|----------------|-----|------|"

  echo "$interfaces" | jq -c '.[]' 2>/dev/null | while read -r iface; do
    local ifname iftype ifstate mtu aliases vlantag
    ifname=$(echo "$iface" | jq_safe '.name')
    iftype=$(echo "$iface" | jq_safe '.type')
    ifstate=$(echo "$iface" | jq_safe '.state.link_state // "unknown"')
    mtu=$(echo "$iface" | jq_safe '.mtu // "N/A"')
    vlantag=$(echo "$iface" | jq_safe '.vlan_tag // "N/A"')

    # Collect IP aliases
    aliases=$(echo "$iface" | jq -r '.aliases[]? | "\(.address)/\(.netmask)"' 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
    if [[ -z "$aliases" ]]; then aliases="none"; fi

    echo "| $ifname | $iftype | $ifstate | $aliases | $mtu | $vlantag |"
  done
  echo ""

  # Static routes
  info "Collecting static routes..."
  local routes
  routes=$(query "staticroute.query" 2>/dev/null || echo "[]")
  if [[ "$routes" != "[]" && "$routes" != "null" && -n "$routes" ]]; then
    echo "### Static Routes"
    echo ""
    echo "| Destination | Gateway | Description |"
    echo "|-------------|---------|-------------|"
    echo "$routes" | jq -c '.[]' 2>/dev/null | while read -r route; do
      local dest gw desc
      dest=$(echo "$route" | jq_safe '.destination')
      gw=$(echo "$route" | jq_safe '.gateway')
      desc=$(echo "$route" | jq_safe '.description // ""')
      echo "| $dest | $gw | $desc |"
    done
    echo ""
  fi
}

collect_services() {
  info "Collecting service status..."
  local services
  services=$(query "service.query")

  md_section 2 "Services"

  echo "| Service | State | Enabled at Boot |"
  echo "|---------|-------|-----------------|"

  echo "$services" | jq -c '.[]' 2>/dev/null | while read -r svc; do
    local sname sstate senabled
    sname=$(echo "$svc" | jq_safe '.service')
    sstate=$(echo "$svc" | jq_safe '.state')
    senabled=$(echo "$svc" | jq_safe '.enable')

    # Emoji indicators
    local state_icon="⚪"
    if [[ "$sstate" == "RUNNING" ]]; then state_icon="🟢"; fi
    if [[ "$sstate" == "STOPPED" ]]; then state_icon="🔴"; fi

    echo "| $sname | $state_icon $sstate | $senabled |"
  done
  echo ""
}

collect_shares() {
  info "Collecting share configuration..."

  md_section 2 "Shares"

  # SMB
  local smb_shares
  smb_shares=$(query "sharing.smb.query" 2>/dev/null || echo "[]")

  echo "### SMB Shares"
  echo ""

  if [[ "$smb_shares" == "[]" || -z "$smb_shares" ]]; then
    echo "_No SMB shares configured._"
  else
    echo "| Name | Path | Enabled | Read Only | Guest OK | Purpose |"
    echo "|------|------|---------|-----------|----------|---------|"
    echo "$smb_shares" | jq -c '.[]' 2>/dev/null | while read -r share; do
      local sname spath senabled sro sguest spurpose
      sname=$(echo "$share" | jq_safe '.name')
      spath=$(echo "$share" | jq_safe '.path // .path_local // "N/A"')
      senabled=$(echo "$share" | jq_safe '.enabled')
      sro=$(echo "$share" | jq_safe '.ro')
      sguest=$(echo "$share" | jq_safe '.guestok')
      spurpose=$(echo "$share" | jq_safe '.purpose // .comment // ""')
      echo "| $sname | $spath | $senabled | $sro | $sguest | $spurpose |"
    done
  fi
  echo ""

  # NFS
  local nfs_shares
  nfs_shares=$(query "sharing.nfs.query" 2>/dev/null || echo "[]")

  echo "### NFS Shares"
  echo ""

  if [[ "$nfs_shares" == "[]" || -z "$nfs_shares" ]]; then
    echo "_No NFS shares configured._"
  else
    echo "| Path | Enabled | Networks | Hosts | MapRoot User | MapAll User |"
    echo "|------|---------|----------|-------|--------------|-------------|"
    echo "$nfs_shares" | jq -c '.[]' 2>/dev/null | while read -r share; do
      local npath nenabled nnetworks nhosts nmaproot nmapall
      npath=$(echo "$share" | jq_safe '.path // .paths[0] // "N/A"')
      nenabled=$(echo "$share" | jq_safe '.enabled')
      nnetworks=$(echo "$share" | jq_safe '.networks | join(", ") // "all"')
      nhosts=$(echo "$share" | jq_safe '.hosts | join(", ") // "all"')
      nmaproot=$(echo "$share" | jq_safe '.maproot_user // "N/A"')
      nmapall=$(echo "$share" | jq_safe '.mapall_user // "N/A"')
      echo "| $npath | $nenabled | $nnetworks | $nhosts | $nmaproot | $nmapall |"
    done
  fi
  echo ""

  # iSCSI (if present)
  local iscsi
  iscsi=$(query "iscsi.target.query" 2>/dev/null || echo "[]")
  if [[ "$iscsi" != "[]" && "$iscsi" != "null" && -n "$iscsi" ]]; then
    echo "### iSCSI Targets"
    echo ""
    echo "| Name | Alias | Mode |"
    echo "|------|-------|------|"
    echo "$iscsi" | jq -c '.[]' 2>/dev/null | while read -r target; do
      local tname talias tmode
      tname=$(echo "$target" | jq_safe '.name')
      talias=$(echo "$target" | jq_safe '.alias // ""')
      tmode=$(echo "$target" | jq_safe '.mode // "N/A"')
      echo "| $tname | $talias | $tmode |"
    done
    echo ""
  fi
}

collect_apps() {
  info "Collecting app/container information..."

  md_section 2 "Apps & Containers"

  # TrueNAS Scale Apps (newer API)
  local apps
  apps=$(query "app.query" 2>/dev/null || echo "[]")

  if [[ "$apps" != "[]" && "$apps" != "null" && -n "$apps" ]]; then
    echo "| App Name | Version | State | Update Available |"
    echo "|----------|---------|-------|------------------|"

    echo "$apps" | jq -c '.[]' 2>/dev/null | while read -r app; do
      local aname aver astate aupdate
      aname=$(echo "$app" | jq_safe '.name // .id')
      aver=$(echo "$app" | jq_safe '.version // .human_version // "N/A"')
      astate=$(echo "$app" | jq_safe '.state // .status // "N/A"')
      aupdate=$(echo "$app" | jq_safe '.update_available // .upgrade_available // false')

      local state_icon="⚪"
      if [[ "$astate" == "RUNNING" || "$astate" == "ACTIVE" ]]; then state_icon="🟢"; fi
      if [[ "$astate" == "STOPPED" || "$astate" == "DEPLOYING" ]]; then state_icon="🟡"; fi

      echo "| $aname | $aver | $state_icon $astate | $aupdate |"
    done
  else
    # Try chart.release.query for older TrueNAS Scale
    local charts
    charts=$(query "chart.release.query" 2>/dev/null || echo "[]")
    if [[ "$charts" != "[]" && "$charts" != "null" && -n "$charts" ]]; then
      echo "| App Name | Version | Status | Chart Version | Catalog |"
      echo "|----------|---------|--------|---------------|---------|"

      echo "$charts" | jq -c '.[]' 2>/dev/null | while read -r chart; do
        local cname cver cstatus cchartver ccat
        cname=$(echo "$chart" | jq_safe '.name')
        cver=$(echo "$chart" | jq_safe '.human_version // "N/A"')
        cstatus=$(echo "$chart" | jq_safe '.status')
        cchartver=$(echo "$chart" | jq_safe '.chart_metadata.version // "N/A"')
        ccat=$(echo "$chart" | jq_safe '.catalog // "N/A"')
        echo "| $cname | $cver | $cstatus | $cchartver | $ccat |"
      done
    else
      echo "_No apps or chart releases found._"
    fi
  fi
  echo ""

  # Docker containers if accessible
  if command -v docker &>/dev/null 2>/dev/null; then
    info "Collecting Docker container info..."
    echo "### Docker Containers"
    echo ""
    echo '```'
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "Docker not accessible"
    echo '```'
    echo ""
  fi
}

collect_vms() {
  info "Collecting VM information..."
  local vms
  vms=$(query "vm.query" 2>/dev/null || echo "[]")

  md_section 2 "Virtual Machines"

  if [[ "$vms" == "[]" || "$vms" == "null" || -z "$vms" ]]; then
    echo "_No virtual machines configured._"
    echo ""
    return
  fi

  echo "| VM Name | Status | vCPUs | RAM | Autostart | Description |"
  echo "|---------|--------|-------|-----|-----------|-------------|"

  echo "$vms" | jq -c '.[]' 2>/dev/null | while read -r vm; do
    local vname vstatus vcpus vram vauto vdesc
    vname=$(echo "$vm" | jq_safe '.name')
    vstatus=$(echo "$vm" | jq_safe '.status.state // "UNKNOWN"')
    vcpus=$(echo "$vm" | jq_safe '.vcpus')
    vram=$(echo "$vm" | jq_safe '.memory')
    vauto=$(echo "$vm" | jq_safe '.autostart')
    vdesc=$(echo "$vm" | jq_safe '.description // ""')

    local ram_human
    local vram_int=${vram%%.*}
    ram_human=$(human_bytes $((vram_int * 1048576)) 2>/dev/null || echo "${vram}MB")

    local state_icon="⚪"
    if [[ "$vstatus" == "RUNNING" ]]; then state_icon="🟢"; fi
    if [[ "$vstatus" == "STOPPED" ]]; then state_icon="🔴"; fi

    echo "| $vname | $state_icon $vstatus | $vcpus | $ram_human | $vauto | $vdesc |"
  done
  echo ""

  # VM device details
  echo "### VM Device Details"
  echo ""
  echo "$vms" | jq -c '.[]' 2>/dev/null | while read -r vm; do
    local vname
    vname=$(echo "$vm" | jq_safe '.name')
    echo "**$vname:**"
    echo ""
    echo "$vm" | jq -c '.devices[]?' 2>/dev/null | while read -r dev; do
      local dtype dattrs
      dtype=$(echo "$dev" | jq_safe '.dtype')
      dattrs=$(echo "$dev" | jq_safe 'del(.id, .vm, .dtype, .order) | to_entries | map("\(.key)=\(.value)") | join(", ")')
      echo "- \`$dtype\`: $dattrs"
    done
    echo ""
  done
}

collect_alerts() {
  info "Collecting alerts..."
  local alerts
  alerts=$(query "alert.list" 2>/dev/null || echo "[]")

  md_section 2 "Current Alerts"

  if [[ "$alerts" == "[]" || "$alerts" == "null" || -z "$alerts" ]]; then
    echo "_No active alerts. ✅_"
    echo ""
    return
  fi

  echo "| Level | Alert | Source | Datetime |"
  echo "|-------|-------|--------|----------|"

  echo "$alerts" | jq -c '.[]' 2>/dev/null | while read -r alert; do
    local alevel amsg asrc adatetime
    alevel=$(echo "$alert" | jq_safe '.level')
    amsg=$(echo "$alert" | jq_safe '.formatted // .text // "N/A"')
    asrc=$(echo "$alert" | jq_safe '.source // "N/A"')
    adatetime=$(echo "$alert" | jq_safe '.datetime // "N/A"')

    local level_icon="ℹ️"
    case "$alevel" in
      CRITICAL) level_icon="🔴";;
      WARNING)  level_icon="🟡";;
      NOTICE)   level_icon="🔵";;
    esac

    echo "| $level_icon $alevel | $amsg | $asrc | $adatetime |"
  done
  echo ""
}

collect_updates() {
  info "Checking for updates..."
  local updates
  updates=$(query "update.check_available" 2>/dev/null || echo "{}")

  md_section 2 "System Updates"

  local status version changelog
  status=$(echo "$updates" | jq_safe '.status')
  version=$(echo "$updates" | jq_safe '.version // "N/A"')
  changelog=$(echo "$updates" | jq_safe '.changelog // "N/A"')

  echo "| Property | Value |"
  echo "|----------|-------|"
  echo "| **Update Status** | $status |"
  echo "| **Available Version** | $version |"

  if [[ "$changelog" != "N/A" && "$changelog" != "null" ]]; then
    echo ""
    echo "**Changelog:**"
    echo "$changelog" | head -20
  fi
  echo ""
}

collect_replication() {
  info "Collecting replication tasks..."
  local tasks
  tasks=$(query "replication.query" 2>/dev/null || echo "[]")

  md_section 2 "Replication Tasks"

  if [[ "$tasks" == "[]" || "$tasks" == "null" || -z "$tasks" ]]; then
    echo "_No replication tasks configured._"
    echo ""
    return
  fi

  echo "| Name | Direction | Source | Target | Enabled | Last Run | State |"
  echo "|------|-----------|--------|--------|---------|----------|-------|"

  echo "$tasks" | jq -c '.[]' 2>/dev/null | while read -r task; do
    local tname tdir tsrc ttgt tenabled tlast tstate
    tname=$(echo "$task" | jq_safe '.name')
    tdir=$(echo "$task" | jq_safe '.direction')
    tsrc=$(echo "$task" | jq_safe '.source_datasets | join(", ") // "N/A"')
    ttgt=$(echo "$task" | jq_safe '.target_dataset // "N/A"')
    tenabled=$(echo "$task" | jq_safe '.enabled')
    tstate=$(echo "$task" | jq_safe '.state.state // "N/A"')
    tlast=$(echo "$task" | jq_safe '.state.datetime // "N/A"')
    echo "| $tname | $tdir | $tsrc | $ttgt | $tenabled | $tlast | $tstate |"
  done
  echo ""
}

collect_snapshots() {
  info "Collecting snapshot summary..."

  md_section 2 "Snapshot Summary"

  # Snapshot tasks
  local snap_tasks
  snap_tasks=$(query "pool.snapshottask.query" 2>/dev/null || echo "[]")

  if [[ "$snap_tasks" != "[]" && "$snap_tasks" != "null" ]]; then
    echo "### Scheduled Snapshot Tasks"
    echo ""
    echo "| Dataset | Recursive | Lifetime | Enabled | Schedule |"
    echo "|---------|-----------|----------|---------|----------|"

    echo "$snap_tasks" | jq -c '.[]' 2>/dev/null | while read -r task; do
      local tds trecur tlife tenabled tsched
      tds=$(echo "$task" | jq_safe '.dataset')
      trecur=$(echo "$task" | jq_safe '.recursive')
      tlife=$(echo "$task" | jq_safe '"\(.lifetime_value) \(.lifetime_unit)"')
      tenabled=$(echo "$task" | jq_safe '.enabled')
      tsched=$(echo "$task" | jq_safe '.schedule | "\(.hour):\(.minute) \(.dom)/\(.month)/\(.dow)"')
      echo "| $tds | $trecur | $tlife | $tenabled | $tsched |"
    done
    echo ""
  fi

  # Count snapshots per dataset
  local snapshots
  snapshots=$(query "zfs.snapshot.query" '[[],{"select":["name","dataset"]}]' 2>/dev/null || echo "[]")

  if [[ "$snapshots" != "[]" && "$snapshots" != "null" ]]; then
    echo "### Snapshot Counts by Dataset"
    echo ""
    echo "| Dataset | Snapshot Count |"
    echo "|---------|---------------|"
    echo "$snapshots" | jq -r '.[].dataset' 2>/dev/null | sort | uniq -c | sort -rn | head -20 | while read -r count ds; do
      echo "| $ds | $count |"
    done
    echo ""
  fi
}

collect_cron() {
  info "Collecting cron tasks..."
  local cron_tasks
  cron_tasks=$(query "cronjob.query" 2>/dev/null || echo "[]")

  md_section 2 "Cron Jobs"

  if [[ "$cron_tasks" == "[]" || "$cron_tasks" == "null" || -z "$cron_tasks" ]]; then
    echo "_No cron jobs configured._"
    echo ""
    return
  fi

  echo "| Description | Command | User | Enabled | Schedule |"
  echo "|-------------|---------|------|---------|----------|"

  echo "$cron_tasks" | jq -c '.[]' 2>/dev/null | while read -r task; do
    local tdesc tcmd tuser tenabled tsched
    tdesc=$(echo "$task" | jq_safe '.description // "N/A"')
    tcmd=$(echo "$task" | jq_safe '.command' | head -c 60)
    tuser=$(echo "$task" | jq_safe '.user')
    tenabled=$(echo "$task" | jq_safe '.enabled')
    tsched=$(echo "$task" | jq_safe '.schedule | "\(.minute) \(.hour) \(.dom) \(.month) \(.dow)"')
    echo "| $tdesc | \`$tcmd\` | $tuser | $tenabled | $tsched |"
  done
  echo ""
}

collect_boot() {
  info "Collecting boot pool info..."
  local boot
  boot=$(query "boot.get_state" 2>/dev/null || echo "{}")

  md_section 2 "Boot Pool"

  local name status scan_state
  name=$(echo "$boot" | jq_safe '.name // "boot-pool"')
  status=$(echo "$boot" | jq_safe '.status // .properties.health.value // "N/A"')
  scan_state=$(echo "$boot" | jq_safe '.scan.state // "N/A"')

  echo "| Property | Value |"
  echo "|----------|-------|"
  echo "| **Name** | $name |"
  echo "| **Status** | $status |"
  echo "| **Scan State** | $scan_state |"
  echo ""

  # Boot pool disks
  echo "**Boot Devices:**"
  echo ""
  echo '```'
  echo "$boot" | jq -r '
    .groups // .topology | to_entries[] |
    .value[] |
    "\(.type // "N/A") - \(.status // "N/A")",
    (.children[]? | "  └─ \(.path // "unknown") [\(.status // "N/A")]")
  ' 2>/dev/null || echo "(unable to parse boot topology)"
  echo '```'
  echo ""
}

# ── Composite Commands ──────────────────────────────────────────────────────

generate_full_md() {
  echo "# TrueNAS Configuration"
  echo ""
  echo "> Auto-generated by truenas-toolkit.sh on $(now)"
  echo ">"
  echo "> **Re-run command:** \`./truenas-toolkit.sh full > $MD_FILE\`"
  echo ""
  echo "---"

  collect_system
  collect_pools
  collect_disks
  collect_network
  collect_services
  collect_shares
  collect_apps
  collect_vms
  collect_alerts
  collect_replication
  collect_snapshots
  collect_cron
  collect_boot

  echo ""
  echo "---"
  echo ""
  echo "## Maintenance Notes"
  echo ""
  echo "| Item | Last Performed | Next Due | Notes |"
  echo "|------|---------------|----------|-------|"
  echo "| SMART Test (Long) | | | Schedule monthly |"
  echo "| Scrub | | | Check pool scrub schedule |"
  echo "| Config Backup | | | Export from UI > System > General |"
  echo "| Firmware Update | | | Check release notes first |"
  echo "| Toolkit Refresh | $(date +%Y-%m-%d) | | Re-run \`./truenas-toolkit.sh full\` |"
  echo ""
  echo "## Security Notes"
  echo ""
  echo "- [ ] API key rotated recently"
  echo "- [ ] SSH restricted to management VLAN"
  echo "- [ ] Admin password is strong + unique"
  echo "- [ ] Shares use proper ACLs"
  echo "- [ ] No unnecessary services running"
  echo "- [ ] Boot pool mirrored"
}

generate_diag() {
  echo "# TrueNAS Quick Diagnostic - $(now)"
  echo ""
  echo '```'
  echo "Collected: $(now)"
  echo '```'
  echo ""

  collect_system
  collect_alerts

  # Condensed pool status
  info "Collecting pool health..."
  md_section 2 "Pool Health (Quick)"
  local pools
  pools=$(query "pool.query")

  echo "| Pool | Status | Healthy | Errors |"
  echo "|------|--------|---------|--------|"
  echo "$pools" | jq -c '.[]' 2>/dev/null | while read -r pool; do
    local pname pstatus phealthy perrors
    pname=$(echo "$pool" | jq_safe '.name')
    pstatus=$(echo "$pool" | jq_safe '.status')
    phealthy=$(echo "$pool" | jq_safe '.healthy')
    perrors=$(echo "$pool" | jq_safe '.scan.errors // 0')
    echo "| $pname | $pstatus | $phealthy | $perrors |"
  done
  echo ""

  # Condensed service status (running only)
  info "Collecting running services..."
  md_section 2 "Running Services"
  local services
  services=$(query "service.query")

  echo "$services" | jq -r '.[] | select(.state == "RUNNING") | "- 🟢 \(.service)"' 2>/dev/null
  echo ""

  # Stopped but enabled services (potential issues)
  local stopped_enabled
  stopped_enabled=$(echo "$services" | jq -r '.[] | select(.state != "RUNNING" and .enable == true) | "- 🔴 \(.service) (enabled but not running!)"' 2>/dev/null)
  if [[ -n "$stopped_enabled" ]]; then
    echo "**⚠️ Stopped but Enabled:**"
    echo "$stopped_enabled"
    echo ""
  fi

  # App status (condensed)
  info "Collecting app status..."
  md_section 2 "App Status"
  local apps
  apps=$(query "app.query" 2>/dev/null || echo "[]")

  if [[ "$apps" != "[]" && "$apps" != "null" && -n "$apps" ]]; then
    echo "$apps" | jq -r '.[] | "- \(if .state == "RUNNING" or .state == "ACTIVE" then "🟢" elif .state == "STOPPED" then "🔴" else "🟡" end) \(.name // .id) (\(.state // "N/A"))"' 2>/dev/null
  else
    local charts
    charts=$(query "chart.release.query" 2>/dev/null || echo "[]")
    if [[ "$charts" != "[]" && "$charts" != "null" && -n "$charts" ]]; then
      echo "$charts" | jq -r '.[] | "- \(.status): \(.name)"' 2>/dev/null
    else
      echo "_No apps found._"
    fi
  fi
  echo ""

  echo "---"
  echo "_For full details, run: \`./truenas-toolkit.sh full\`_"
}

# ── Sanitization Module ─────────────────────────────────────────────────────

# Sanitization tracking - maps original values to redacted replacements
declare -A SANITIZE_MAP

sanitize_serial_numbers() {
  local file="$1"
  local count=0
  local -A seen

  # Catch serial numbers from disk table rows and serial fields
  while IFS= read -r serial; do
    [[ -z "$serial" || "$serial" == "N/A" || "$serial" == "null" ]] && continue
    [[ -n "${seen[$serial]+x}" ]] && continue
    seen["$serial"]=1
    count=$((count + 1))
    local redacted="SERIAL-REDACTED-$(printf '%03d' $count)"
    SANITIZE_MAP["$serial"]="$redacted"
    sed -i "s|${serial}|${redacted}|g" "$file"
  done < <(
    # Serials in table columns (6-20 char alphanumeric between pipes)
    grep -oP '(?<=\| )[A-Z0-9]{6,20}(?= \|)' "$file" 2>/dev/null
    # Serials near the word "serial"
    grep -iP 'serial' "$file" 2>/dev/null | grep -oP '[A-Z0-9_-]{8,}'
  )

  echo "  Redacted $count serial number(s)" >&2
}

sanitize_ip_addresses() {
  local file="$1"
  local scope="$2"  # "all", "public", "private"
  local pub_count=0 priv_count=0

  local -a all_ips
  mapfile -t all_ips < <(grep -oP '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' "$file" | sort -u)

  for ip in "${all_ips[@]}"; do
    [[ -z "$ip" ]] && continue
    [[ -n "${SANITIZE_MAP[$ip]+x}" ]] && continue

    local is_private=false
    [[ "$ip" =~ ^10\. ]] && is_private=true
    [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && is_private=true
    [[ "$ip" =~ ^192\.168\. ]] && is_private=true
    [[ "$ip" =~ ^127\. ]] && is_private=true
    [[ "$ip" =~ ^169\.254\. ]] && is_private=true

    if ! $is_private && [[ "$scope" == "all" || "$scope" == "public" ]]; then
      pub_count=$((pub_count + 1))
      local redacted="WAN-IP-REDACTED-$(printf '%03d' $pub_count)"
      SANITIZE_MAP["$ip"]="$redacted"
      sed -i "s|${ip}|${redacted}|g" "$file"
    elif $is_private && [[ "$scope" == "all" || "$scope" == "private" ]]; then
      priv_count=$((priv_count + 1))
      local redacted="PRIV-IP-REDACTED-$(printf '%03d' $priv_count)"
      SANITIZE_MAP["$ip"]="$redacted"
      sed -i "s|${ip}|${redacted}|g" "$file"
    fi
  done

  local total=$((pub_count + priv_count))
  echo "  Redacted $total IP address(es) (scope: $scope — $pub_count public, $priv_count private)" >&2
}

sanitize_mac_addresses() {
  local file="$1"
  local count=0

  while IFS= read -r mac; do
    [[ -z "$mac" ]] && continue
    [[ -n "${SANITIZE_MAP[$mac]+x}" ]] && continue
    count=$((count + 1))
    # Preserve OUI prefix (first 3 octets) for vendor ID, redact device portion
    local prefix="${mac:0:8}"
    local redacted="${prefix}:XX:XX:$(printf '%02X' $count)"
    SANITIZE_MAP["$mac"]="$redacted"
    sed -i "s|${mac}|${redacted}|gi" "$file"
  done < <(grep -oiP '([0-9a-f]{2}:){5}[0-9a-f]{2}' "$file" | sort -u)

  echo "  Redacted $count MAC address(es) (OUI vendor prefix preserved)" >&2
}

sanitize_hostname() {
  local file="$1"
  local hostname
  hostname=$(grep -m1 'Hostname' "$file" | grep -oP '(?<=\| )[^ |]+(?= \|)' | tail -1 || true)

  if [[ -n "$hostname" && "$hostname" != "N/A" && "$hostname" != "**Hostname**" ]]; then
    SANITIZE_MAP["$hostname"]="HOSTNAME-REDACTED"
    sed -i "s|${hostname}|HOSTNAME-REDACTED|g" "$file"
    echo "  Redacted hostname ($hostname)" >&2
  else
    echo "  No hostname found to redact" >&2
  fi
}

sanitize_share_paths() {
  local file="$1"
  local count=0

  while IFS= read -r path; do
    [[ -z "$path" || "$path" == "N/A" ]] && continue
    [[ -n "${SANITIZE_MAP[$path]+x}" ]] && continue
    count=$((count + 1))
    local redacted="/mnt/POOL-REDACTED/share-$(printf '%03d' $count)"
    SANITIZE_MAP["$path"]="$redacted"
    sed -i "s|${path}|${redacted}|g" "$file"
  done < <(grep -oP '/mnt/[A-Za-z0-9/_-]+' "$file" | sort -u)

  echo "  Redacted $count share/dataset path(s)" >&2
}

sanitize_pool_dataset_names() {
  local file="$1"

  echo -e "${CYAN}  Enter pool/dataset names to redact (comma-separated, or 'skip'):${RESET}" >&2
  read -r -p "  > " names_input

  if [[ "$names_input" == "skip" || -z "$names_input" ]]; then
    echo "  Skipped pool/dataset name redaction" >&2
    return
  fi

  local count=0
  IFS=',' read -ra names <<< "$names_input"
  for name in "${names[@]}"; do
    name=$(echo "$name" | xargs)
    [[ -z "$name" ]] && continue
    count=$((count + 1))
    local redacted="POOL-REDACTED-$(printf '%03d' $count)"
    SANITIZE_MAP["$name"]="$redacted"
    sed -i "s|${name}|${redacted}|g" "$file"
  done

  echo "  Redacted $count pool/dataset name(s)" >&2
}

sanitize_usernames() {
  local file="$1"

  echo -e "${CYAN}  Enter usernames to redact (comma-separated, or 'skip'):${RESET}" >&2
  read -r -p "  > " names_input

  if [[ "$names_input" == "skip" || -z "$names_input" ]]; then
    echo "  Skipped username redaction" >&2
    return
  fi

  local count=0
  IFS=',' read -ra names <<< "$names_input"
  for name in "${names[@]}"; do
    name=$(echo "$name" | xargs)
    [[ -z "$name" ]] && continue
    count=$((count + 1))
    local redacted="USER-REDACTED-$(printf '%03d' $count)"
    SANITIZE_MAP["$name"]="$redacted"
    sed -i "s|${name}|${redacted}|g" "$file"
  done

  echo "  Redacted $count username(s)" >&2
}

sanitize_custom() {
  local file="$1"

  echo -e "${CYAN}  Enter custom strings to redact (comma-separated, or 'skip'):${RESET}" >&2
  read -r -p "  > " custom_input

  if [[ "$custom_input" == "skip" || -z "$custom_input" ]]; then
    echo "  Skipped custom redaction" >&2
    return
  fi

  local count=0
  IFS=',' read -ra items <<< "$custom_input"
  for item in "${items[@]}"; do
    item=$(echo "$item" | xargs)
    [[ -z "$item" ]] && continue
    count=$((count + 1))
    local redacted="CUSTOM-REDACTED-$(printf '%03d' $count)"
    SANITIZE_MAP["$item"]="$redacted"
    sed -i "s|${item}|${redacted}|g" "$file"
  done

  echo "  Redacted $count custom string(s)" >&2
}

write_redaction_log() {
  local file="$1"
  local log_file="${file%.md}-redaction-log.txt"

  echo "" >&2
  echo -e "${CYAN}Save redaction map to ${log_file}?${RESET}" >&2
  echo -e "${DIM}  Maps REDACTED values back to originals — keep this private!${RESET}" >&2
  read -r -p "  Save redaction log? [y/N] > " save_log

  if [[ "$save_log" =~ ^[Yy] ]]; then
    {
      echo "# Redaction Log - $(now)"
      echo "# Source: $file"
      echo "# ⚠️  WARNING: Contains sensitive data. Do NOT share."
      echo ""
      echo "| Redacted | Original |"
      echo "|----------|----------|"
      for orig in "${!SANITIZE_MAP[@]}"; do
        echo "| ${SANITIZE_MAP[$orig]} | $orig |"
      done
    } > "$log_file"
    echo -e "  ${GREEN}Saved: $log_file${RESET}" >&2
    echo -e "  ${YELLOW}⚠️  Keep this file private!${RESET}" >&2
  else
    echo "  Redaction log not saved" >&2
  fi
}

interactive_sanitize() {
  local file="$1"

  if [[ ! -f "$file" ]]; then
    err "File not found: $file"
    return 1
  fi

  # Only prompt if interactive terminal
  if [[ ! -t 0 ]]; then
    info "Non-interactive mode — skipping sanitization"
    return 0
  fi

  echo "" >&2
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}" >&2
  echo -e "${BOLD}  Sanitization Options${RESET}" >&2
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}" >&2
  echo "" >&2
  echo -e "  File: ${CYAN}$file${RESET}" >&2
  echo "" >&2
  echo -e "  ${GREEN}1${RESET}) Disk serial numbers" >&2
  echo -e "  ${GREEN}2${RESET}) Public (WAN) IP addresses only" >&2
  echo -e "  ${GREEN}3${RESET}) All IP addresses (public + private)" >&2
  echo -e "  ${GREEN}4${RESET}) MAC addresses (preserves vendor prefix)" >&2
  echo -e "  ${GREEN}5${RESET}) Hostname" >&2
  echo -e "  ${GREEN}6${RESET}) Share/dataset paths" >&2
  echo -e "  ${GREEN}7${RESET}) Pool/dataset names (you type them)" >&2
  echo -e "  ${GREEN}8${RESET}) Usernames (you type them)" >&2
  echo -e "  ${GREEN}9${RESET}) Custom strings (you type them)" >&2
  echo "" >&2
  echo -e "  ${YELLOW}A${RESET}) All automatic (1-6)" >&2
  echo -e "  ${YELLOW}F${RESET}) Full sanitize (1-9, prompts for 7-9)" >&2
  echo -e "  ${YELLOW}S${RESET}) Skip — keep file as-is" >&2
  echo "" >&2

  read -r -p "  Enter choices (e.g. 1,2,4 or A or F or S) > " choices

  if [[ "$choices" =~ ^[Ss]$ || -z "$choices" ]]; then
    echo -e "  ${DIM}Skipping sanitization${RESET}" >&2
    return 0
  fi

  # Expand shortcuts
  [[ "$choices" =~ ^[Aa]$ ]] && choices="1,2,4,5,6"
  [[ "$choices" =~ ^[Ff]$ ]] && choices="1,2,4,5,6,7,8,9"

  echo "" >&2
  echo -e "${BOLD}Sanitizing...${RESET}" >&2

  # Backup
  cp "$file" "${file}.bak"
  echo -e "  ${DIM}Backup: ${file}.bak${RESET}" >&2
  echo "" >&2

  IFS=',' read -ra selected <<< "$choices"
  for choice in "${selected[@]}"; do
    choice=$(echo "$choice" | xargs)
    case "$choice" in
      1) sanitize_serial_numbers "$file" ;;
      2) sanitize_ip_addresses "$file" "public" ;;
      3) sanitize_ip_addresses "$file" "all" ;;
      4) sanitize_mac_addresses "$file" ;;
      5) sanitize_hostname "$file" ;;
      6) sanitize_share_paths "$file" ;;
      7) sanitize_pool_dataset_names "$file" ;;
      8) sanitize_usernames "$file" ;;
      9) sanitize_custom "$file" ;;
      *) echo "  Unknown option: $choice (skipping)" >&2 ;;
    esac
  done

  echo "" >&2
  echo -e "${BOLD}Sanitization complete.${RESET}" >&2
  echo -e "  Total redactions: ${#SANITIZE_MAP[@]}" >&2
  echo -e "  Sanitized file:   ${GREEN}$file${RESET}" >&2
  echo -e "  Original backup:  ${DIM}${file}.bak${RESET}" >&2

  if [[ ${#SANITIZE_MAP[@]} -gt 0 ]]; then
    write_redaction_log "$file"
  fi

  echo "" >&2
  echo -e "${DIM}Restore original:  mv ${file}.bak $file${RESET}" >&2
  echo -e "${DIM}Delete backup:     rm ${file}.bak${RESET}" >&2
}

# ── Argument Parsing ────────────────────────────────────────────────────────

# Parse flags
SKIP_SANITIZE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote|-r)
      REMOTE_MODE=true
      shift
      ;;
    --host)
      TRUENAS_HOST="$2"
      shift 2
      ;;
    --api-key)
      TRUENAS_API_KEY="$2"
      shift 2
      ;;
    --no-sanitize)
      SKIP_SANITIZE=true
      shift
      ;;
    --output|-o)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    --md-file)
      MD_FILE="$2"
      shift 2
      ;;
    -*)
      err "Unknown flag: $1"
      usage
      ;;
    *)
      break
      ;;
  esac
done

COMMAND="${1:-help}"
COMMAND_ARG="${2:-}"

# Execute
run_command() {
  case "$COMMAND" in
    full)       generate_full_md ;;
    diag)       generate_diag ;;
    sanitize)
      # Standalone sanitize: sanitize an existing file
      local target="${COMMAND_ARG:-$MD_FILE}"
      if [[ ! -f "$target" ]]; then
        err "File not found: $target"
        echo "Usage: $0 sanitize [filename]  (default: $MD_FILE)"
        exit 1
      fi
      interactive_sanitize "$target"
      exit 0
      ;;
    system)     collect_system ;;
    pools)      collect_pools ;;
    disks)      collect_disks ;;
    smart)      collect_smart ;;
    network)    collect_network ;;
    services)   collect_services ;;
    shares)     collect_shares ;;
    apps)       collect_apps ;;
    vms)        collect_vms ;;
    alerts)     collect_alerts ;;
    updates)    collect_updates ;;
    replication) collect_replication ;;
    snapshots)  collect_snapshots ;;
    cron)       collect_cron ;;
    boot)       collect_boot ;;
    help|--help|-h)
      echo -e "${BOLD}TrueNAS Diagnostic Toolkit${RESET}"
      echo ""
      echo "Usage: $0 [--remote] [--host IP] [--api-key KEY] [-o FILE] <command>"
      echo ""
      echo "Commands:"
      echo "  full         Generate complete truenas_config.md"
      echo "  diag         Quick diagnostic summary (paste into chat)"
      echo "  sanitize     Sanitize an existing file (default: truenas_config.md)"
      echo "  system       System info (CPU, RAM, OS, uptime)"
      echo "  pools        Pool status and dataset usage"
      echo "  disks        Disk inventory"
      echo "  smart        Detailed SMART health data"
      echo "  network      Network interfaces and config"
      echo "  services     Service status"
      echo "  shares       SMB, NFS, iSCSI shares"
      echo "  apps         Apps and containers"
      echo "  vms          Virtual machines"
      echo "  alerts       Current system alerts"
      echo "  updates      Available system updates"
      echo "  replication  Replication task status"
      echo "  snapshots    Snapshot summary"
      echo "  cron         Cron job configuration"
      echo "  boot         Boot pool status"
      echo "  help         Show this help"
      echo ""
      echo "Flags:"
      echo "  --remote, -r       Use REST API instead of local midclt"
      echo "  --host IP          TrueNAS hostname/IP (default: \$TRUENAS_HOST)"
      echo "  --api-key KEY      API key (default: \$TRUENAS_API_KEY)"
      echo "  -o, --output FILE  Write output to file instead of stdout"
      echo "  --md-file FILE     Filename for full markdown (default: truenas_config.md)"
      echo "  --no-sanitize      Skip sanitization prompt"
      echo ""
      echo "Examples:"
      echo "  # SSH into TrueNAS and generate full doc:"
      echo "  ./truenas-toolkit.sh full > truenas_config.md"
      echo ""
      echo "  # Quick diagnostic to paste into chat:"
      echo "  ./truenas-toolkit.sh diag | pbcopy"
      echo ""
      echo "  # Remote API - check pools:"
      echo "  TRUENAS_API_KEY=mykey ./truenas-toolkit.sh --remote --host 192.168.10.5 pools"
      echo ""
      echo "  # Check just alerts and services:"
      echo "  ./truenas-toolkit.sh alerts"
      echo "  ./truenas-toolkit.sh services"
      echo ""
      echo "  # Sanitize an existing file:"
      echo "  ./truenas-toolkit.sh sanitize truenas_config.md"
      echo ""
      echo "  # Generate without sanitization prompt:"
      echo "  ./truenas-toolkit.sh --no-sanitize -o truenas_config.md full"
      ;;
    *)
      err "Unknown command: $COMMAND"
      echo "Run '$0 help' for usage."
      exit 1
      ;;
  esac
}

if [[ -n "$OUTPUT_FILE" ]]; then
  run_command > "$OUTPUT_FILE"
  info "Output written to $OUTPUT_FILE"
  # Offer sanitization for file output
  if ! $SKIP_SANITIZE && [[ "$COMMAND" == "full" || "$COMMAND" == "diag" ]]; then
    interactive_sanitize "$OUTPUT_FILE"
  fi
elif [[ "$COMMAND" == "full" || "$COMMAND" == "diag" ]]; then
  # For full/diag without -o, write to default file and offer sanitization
  DEFAULT_OUT="$MD_FILE"
  [[ "$COMMAND" == "diag" ]] && DEFAULT_OUT="truenas_diag_$(date +%Y%m%d_%H%M%S).md"

  if [[ -t 1 ]]; then
    # Interactive terminal — ask about file output
    echo "" >&2
    echo -e "${CYAN}Write output to file for sanitization?${RESET}" >&2
    read -r -p "  Filename (enter for '$DEFAULT_OUT', 'n' to print to stdout only) > " file_choice

    if [[ "$file_choice" =~ ^[Nn]$ ]]; then
      run_command
    else
      [[ -n "$file_choice" ]] && DEFAULT_OUT="$file_choice"
      run_command > "$DEFAULT_OUT"
      info "Output written to $DEFAULT_OUT"
      if ! $SKIP_SANITIZE; then
        interactive_sanitize "$DEFAULT_OUT"
      fi
    fi
  else
    # Non-interactive (piped) — just output to stdout
    run_command
  fi
else
  run_command
fi
