#!/bin/bash
###############################################################################
# UniFi JSON-to-Docs Converter
# Purpose: Convert unifi-api-toolkit.sh JSON exports into documentation
#          markdown files for the home network knowledge base.
#
# Usage:
#   ./unifi-json-to-docs.sh [export-dir] [output-dir]
#
# Defaults:
#   export-dir:  ./unifi-exports          (or ./unifi-exports/sanitized if exists)
#   output-dir:  ./Documents
#
# Generates (into Documents subfolder structure):
#   infrastructure/
#     network_topology.md    ← networks.json + firewall_zones.json
#   devices/
#     equipment_list.md      ← devices.json
#     clients.md             ← clients.json (if present)
#   security/
#     firewall_rules.md      ← firewall_policies.json + firewall_zones.json + networks.json
#     port_forwarding.md     ← port-forwarding.json (if present)
#   operations/
#     change_log.md          ← auto-generated entry for this export
#     _CONSISTENCY_CHECK.md  ← cross-reference audit
#
# Requirements: jq
# Companion to: unifi-api-toolkit.sh
###############################################################################

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

EXPORT_DIR="${1:-./unifi-exports}"
OUTPUT_DIR="${2:-./Documents}"

# Prefer sanitized/ subdirectory if it exists and no explicit dir given
if [ "$#" -lt 1 ] && [ -d "${EXPORT_DIR}/sanitized" ]; then
    EXPORT_DIR="${EXPORT_DIR}/sanitized"
fi

# ─── Output Subdirectories (Documents folder structure) ─────────────────────
DIR_INFRASTRUCTURE="${OUTPUT_DIR}/infrastructure"
DIR_DEVICES="${OUTPUT_DIR}/devices"
DIR_SECURITY="${OUTPUT_DIR}/security"
DIR_OPERATIONS="${OUTPUT_DIR}/operations"

DATE_NOW=$(date '+%Y-%m-%d %H:%M:%S')
DATE_SHORT=$(date '+%Y-%m-%d')

# ─── Colors ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

# ─── Validation ──────────────────────────────────────────────────────────────

if ! command -v jq &>/dev/null; then
    log_error "jq is required. Install with: sudo apt install jq"
    exit 1
fi

if [ ! -d "$EXPORT_DIR" ]; then
    log_error "Export directory not found: ${EXPORT_DIR}"
    echo "  Run unifi-api-toolkit.sh first, then point this script at the output."
    exit 1
fi

if [ ! -f "${EXPORT_DIR}/networks.json" ] && [ ! -f "${EXPORT_DIR}/devices.json" ]; then
    log_error "No networks.json or devices.json found in ${EXPORT_DIR}"
    echo "  Expected JSON exports from unifi-api-toolkit.sh"
    exit 1
fi

mkdir -p "$DIR_INFRASTRUCTURE" "$DIR_DEVICES" "$DIR_SECURITY" "$DIR_OPERATIONS"

# ─── Helpers ─────────────────────────────────────────────────────────────────

# Extract the data array — handles nested .data.data and flat .data
get_data() {
    local file="$1"
    [ ! -f "$file" ] && echo '[]' && return

    jq -c '
        if .data.data then
            if (.data.data | type) == "array" then .data.data
            else [.data.data]
            end
        elif .data then
            if (.data | type) == "array" then .data
            else [.data]
            end
        else []
        end
    ' "$file" 2>/dev/null || echo '[]'
}

get_count() {
    local file="$1"
    [ ! -f "$file" ] && echo "0" && return
    get_data "$file" | jq 'length' 2>/dev/null || echo "0"
}

get_source_host() {
    for f in "${EXPORT_DIR}"/*.json; do
        [ ! -f "$f" ] && continue
        local host
        host=$(jq -r '._metadata.source // empty' "$f" 2>/dev/null)
        if [ -n "$host" ]; then echo "$host"; return; fi
    done
    echo "unknown"
}

get_export_date() {
    for f in "${EXPORT_DIR}"/*.json; do
        [ ! -f "$f" ] && continue
        local d
        d=$(jq -r '._metadata.exported // empty' "$f" 2>/dev/null)
        if [ -n "$d" ]; then echo "$d"; return; fi
    done
    echo "unknown"
}

# ─── Build lookup maps ──────────────────────────────────────────────────────
# Used across generators to resolve UUIDs → human names

ZONE_MAP_FILE=""
NETWORK_MAP_FILE=""

build_lookups() {
    ZONE_MAP_FILE=$(mktemp)
    NETWORK_MAP_FILE=$(mktemp)

    # Zone ID → Zone Name
    if [ -f "${EXPORT_DIR}/firewall_zones.json" ]; then
        get_data "${EXPORT_DIR}/firewall_zones.json" | \
            jq -r '.[] | "\(.id)\t\(.name)"' > "$ZONE_MAP_FILE" 2>/dev/null || true
    fi

    # Network ID → "Name (VLAN X)"
    if [ -f "${EXPORT_DIR}/networks.json" ]; then
        get_data "${EXPORT_DIR}/networks.json" | \
            jq -r '.[] | "\(.id)\t\(.name) (VLAN \(.vlanId // "untagged"))"' > "$NETWORK_MAP_FILE" 2>/dev/null || true
    fi
}

cleanup_lookups() {
    rm -f "$ZONE_MAP_FILE" "$NETWORK_MAP_FILE" 2>/dev/null || true
}
trap cleanup_lookups EXIT

resolve_zone() {
    local zone_id="$1"
    [ -z "$zone_id" ] || [ "$zone_id" = "null" ] || [ "$zone_id" = "any" ] && echo "any" && return
    local name
    name=$(grep "^${zone_id}" "$ZONE_MAP_FILE" 2>/dev/null | head -1 | cut -f2)
    if [ -n "$name" ]; then
        echo "$name"
    else
        echo "${zone_id:0:8}…"
    fi
}

resolve_network() {
    local net_id="$1"
    [ -z "$net_id" ] || [ "$net_id" = "null" ] && echo "—" && return
    local name
    name=$(grep "^${net_id}" "$NETWORK_MAP_FILE" 2>/dev/null | head -1 | cut -f2)
    if [ -n "$name" ]; then
        echo "$name"
    else
        echo "${net_id:0:8}…"
    fi
}

# ─── Document Generators ────────────────────────────────────────────────────

generate_network_topology() {
    local outfile="${DIR_INFRASTRUCTURE}/network_topology.md"
    local source_host export_date
    source_host=$(get_source_host)
    export_date=$(get_export_date)

    log_section "Generating infrastructure/network_topology.md"

    cat > "$outfile" << EOF
# Network Topology

> Auto-generated from UniFi API export on ${DATE_SHORT}
> Source: ${source_host} | Export: ${export_date}
> **Review and supplement with manual details (subnets, DHCP ranges, diagram)**
>
> ⚠️ The UniFi Integration API does not expose subnet, gateway, or DHCP configuration.
> Fill these in manually from Network → Settings → Networks in the UniFi UI.

EOF

    # ── VLAN / Network Structure ──
    if [ -f "${EXPORT_DIR}/networks.json" ]; then
        local net_count
        net_count=$(get_count "${EXPORT_DIR}/networks.json")

        echo "## VLAN Structure" >> "$outfile"
        echo "" >> "$outfile"
        echo "| VLAN ID | Name | Zone | Subnet | Gateway | DHCP Range | Origin | Default | Enabled |" >> "$outfile"
        echo "|---------|------|------|--------|---------|------------|--------|---------|---------|" >> "$outfile"

        get_data "${EXPORT_DIR}/networks.json" | jq -r '
            sort_by(.vlanId // 0) | .[] |
            [
                (.vlanId // "untagged" | tostring),
                (.name // "—"),
                (.zoneId // ""),
                (.metadata.origin // "—"),
                (if .default then "⭐" else "" end),
                (if .enabled then "✅" else "❌" end),
                (.id // "—")
            ] | @tsv
        ' 2>/dev/null | while IFS=$'\t' read -r vlan_id name zone_id origin is_default enabled net_id; do
            local zone_name
            zone_name=$(resolve_zone "$zone_id")
            echo "| ${vlan_id} | ${name} | ${zone_name} | <!-- TODO --> | <!-- TODO --> | <!-- TODO --> | ${origin} | ${is_default} | ${enabled} |" >> "$outfile"
        done

        echo "" >> "$outfile"
        echo "> ⭐ = Default network" >> "$outfile"
        echo "" >> "$outfile"

        log_info "Networks: ${net_count} entries"

        # ── Network Details ──
        echo "### Network Details" >> "$outfile"
        echo "" >> "$outfile"

        get_data "${EXPORT_DIR}/networks.json" | jq -r '
            sort_by(.vlanId // 0) | .[] |
            [
                (.name // "Unnamed"),
                (.vlanId // "untagged" | tostring),
                (.management // "—"),
                (.zoneId // ""),
                (.metadata.origin // "—"),
                (if .enabled then "true" else "false" end),
                (if .default then "true" else "false" end),
                (.id // "—")
            ] | @tsv
        ' 2>/dev/null | while IFS=$'\t' read -r name vlan_id mgmt zone_id origin enabled is_default net_id; do
            local zone_name
            zone_name=$(resolve_zone "$zone_id")
            {
                echo "#### ${name}"
                echo "- **VLAN ID:** ${vlan_id}"
                echo "- **Zone:** ${zone_name}"
                echo "- **Management:** ${mgmt}"
                echo "- **Origin:** ${origin}"
                echo "- **Enabled:** ${enabled}"
                echo "- **Default Network:** ${is_default}"
                echo "- **Subnet:** <!-- TODO: fill from UniFi UI -->"
                echo "- **Gateway:** <!-- TODO: fill from UniFi UI -->"
                echo "- **DHCP Range:** <!-- TODO: fill from UniFi UI -->"
                echo "- **Network ID:** \`${net_id}\`"
                echo "- **Zone ID:** \`${zone_id}\`"
                echo ""
            } >> "$outfile"
        done
    else
        echo "## VLAN Structure" >> "$outfile"
        echo "" >> "$outfile"
        echo "> ⚠️ networks.json not found — run \`unifi-api-toolkit.sh quick\`" >> "$outfile"
        echo "" >> "$outfile"
        log_warn "networks.json not found"
    fi

    # ── Firewall Zones ──
    if [ -f "${EXPORT_DIR}/firewall_zones.json" ]; then
        local zone_count
        zone_count=$(get_count "${EXPORT_DIR}/firewall_zones.json")

        echo "## Firewall Zones" >> "$outfile"
        echo "" >> "$outfile"
        echo "| Zone Name | Networks | Origin | Configurable |" >> "$outfile"
        echo "|-----------|----------|--------|-------------|" >> "$outfile"

        get_data "${EXPORT_DIR}/firewall_zones.json" | jq -c '
            sort_by(.name) | .[]
        ' 2>/dev/null | while IFS= read -r zone_json; do
            local zone_name origin configurable
            zone_name=$(echo "$zone_json" | jq -r '.name // "—"')
            origin=$(echo "$zone_json" | jq -r '.metadata.origin // "—"')
            configurable=$(echo "$zone_json" | jq -r '.metadata.configurable // "—"')

            # Resolve network IDs
            local net_names=""
            while IFS= read -r nid; do
                [ -z "$nid" ] && continue
                local resolved
                resolved=$(resolve_network "$nid")
                if [ -n "$net_names" ]; then
                    net_names="${net_names}, ${resolved}"
                else
                    net_names="${resolved}"
                fi
            done < <(echo "$zone_json" | jq -r '.networkIds[]? // empty' 2>/dev/null)
            [ -z "$net_names" ] && net_names="—"

            echo "| ${zone_name} | ${net_names} | ${origin} | ${configurable} |" >> "$outfile"
        done

        echo "" >> "$outfile"
        log_info "Zones: ${zone_count} entries"
    fi

    # ── Diagram placeholder ──
    {
        echo ""
        echo "## Network Diagram"
        echo ""
        echo "> TODO: Update VLAN IDs and names from the table above."
        echo ""
        echo '```'
        echo "Internet"
        echo "    │"
        echo "    ▼"
        echo "[ ISP Modem ] ─── WAN"
        echo "    │"
        echo "    ▼"
        echo "[ UDM Pro Max ]"
        echo "    │"
    } >> "$outfile"

    # Auto-populate from networks data
    if [ -f "${EXPORT_DIR}/networks.json" ]; then
        local last_idx
        last_idx=$(get_data "${EXPORT_DIR}/networks.json" | jq 'length - 1' 2>/dev/null || echo "0")
        local cur_idx=0

        get_data "${EXPORT_DIR}/networks.json" | jq -r '
            sort_by(.vlanId // 0) | .[] |
            "\(.vlanId // "?")\t\(.name // "?")"
        ' 2>/dev/null | while IFS=$'\t' read -r vid vname; do
            if [ "$cur_idx" -eq "$last_idx" ]; then
                echo "    └── VLAN ${vid} ── ${vname}" >> "$outfile"
            else
                echo "    ├── VLAN ${vid} ── ${vname}" >> "$outfile"
            fi
            cur_idx=$((cur_idx + 1))
        done
    fi

    {
        echo '```'
        echo ""
        echo "## Inter-VLAN Routing Policy"
        echo ""
        echo "> Reference \`<<firewall_rules.md>>\` for full policy details."
        echo ""
        echo "| Source Zone | Destination Zone | Default Policy | Notes |"
        echo "|-------------|-----------------|----------------|-------|"
        echo "| <!-- fill in --> | <!-- fill in --> | <!-- ALLOW/BLOCK --> | <!-- notes --> |"
        echo ""
        echo "## Static IP Assignments"
        echo ""
        echo "> TODO: Document static IPs / DHCP reservations"
        echo ""
        echo "| Device | IP | VLAN | MAC | Purpose |"
        echo "|--------|-----|------|-----|---------|"
        echo "| <!-- fill in --> | <!-- IP --> | <!-- VLAN --> | <!-- MAC --> | <!-- purpose --> |"
        echo ""
    } >> "$outfile"

    log_info "Saved: ${outfile}"
}

generate_equipment_list() {
    local outfile="${DIR_DEVICES}/equipment_list.md"

    log_section "Generating devices/equipment_list.md"

    if [ ! -f "${EXPORT_DIR}/devices.json" ]; then
        log_warn "devices.json not found — skipping"
        return
    fi

    local dev_count source_host export_date
    dev_count=$(get_count "${EXPORT_DIR}/devices.json")
    source_host=$(get_source_host)
    export_date=$(get_export_date)

    cat > "$outfile" << EOF
# Equipment Inventory

> Auto-generated from UniFi API export on ${DATE_SHORT}
> Source: ${source_host} | Export: ${export_date}
> UniFi Devices: ${dev_count}

## UniFi Devices

| Name | Model | IP Address | MAC Address | State | Firmware | Updatable | Features |
|------|-------|-----------|-------------|-------|----------|-----------|----------|
EOF

    get_data "${EXPORT_DIR}/devices.json" | jq -r '
        sort_by(.name // "") | .[] |
        "| \(.name // "unnamed") | \(.model // "—") | \(.ipAddress // "—") | \(.macAddress // "—") | \(.state // "—") | \(.firmwareVersion // "—") | \(if .firmwareUpdatable then "⚠️ Yes" else "✅ Current" end) | \((.features // []) | join(", ")) |"
    ' >> "$outfile" 2>/dev/null

    echo "" >> "$outfile"

    # ── Device Details ──
    echo "## Device Details" >> "$outfile"
    echo "" >> "$outfile"

    get_data "${EXPORT_DIR}/devices.json" | jq -r '
        sort_by(.name // "") | .[] |
        "### \(.name // "Unnamed")\n" +
        "- **Model:** \(.model // "—")\n" +
        "- **IP Address:** \(.ipAddress // "—")\n" +
        "- **MAC Address:** \(.macAddress // "—")\n" +
        "- **State:** \(.state // "—")\n" +
        "- **Firmware:** \(.firmwareVersion // "—")\n" +
        "- **Firmware Updatable:** \(if .firmwareUpdatable then "⚠️ Yes" else "No" end)\n" +
        "- **Supported:** \(.supported // false)\n" +
        "- **Features:** \((.features // []) | join(", "))\n" +
        "- **Interfaces:** \((.interfaces // []) | join(", "))\n" +
        "- **Device ID:** `\(.id // "—")`\n"
    ' >> "$outfile" 2>/dev/null

    echo "" >> "$outfile"

    cat >> "$outfile" << 'PLACEHOLDER'
## Non-UniFi Equipment

> TODO: Add non-UniFi devices (TrueNAS, Home Assistant, cameras, etc.)

| Device | Type | Location | IP | VLAN | MAC | Notes |
|--------|------|----------|-----|------|-----|-------|
| <!-- e.g. TrueNAS --> | <!-- server --> | <!-- location --> | <!-- IP --> | <!-- VLAN --> | <!-- MAC --> | <!-- notes --> |

## Firmware Update Tracking

> Track firmware update history

| Device | Current FW | Last Updated | Auto-Update | Notes |
|--------|-----------|-------------|-------------|-------|
| <!-- from table above --> | <!-- version --> | <!-- date --> | <!-- yes/no --> | <!-- notes --> |

PLACEHOLDER

    log_info "Saved: ${outfile} (${dev_count} devices)"
}

generate_firewall_rules() {
    local outfile="${DIR_SECURITY}/firewall_rules.md"

    log_section "Generating security/firewall_rules.md"

    local source_host export_date
    source_host=$(get_source_host)
    export_date=$(get_export_date)

    cat > "$outfile" << EOF
# Firewall Rules

> Auto-generated from UniFi API export on ${DATE_SHORT}
> Source: ${source_host} | Export: ${export_date}
>
> **Note:** Policies reference traffic matching lists by UUID.
> Export group details: \`unifi-api-toolkit.sh raw firewall/groups\`
> Or view in UI: Network → Settings → Profiles → IP Groups / Port Groups

EOF

    # ── Zone Reference ──
    if [ -f "${EXPORT_DIR}/firewall_zones.json" ]; then
        echo "## Zone Reference" >> "$outfile"
        echo "" >> "$outfile"
        echo "| Zone | ID (short) | Network Count |" >> "$outfile"
        echo "|------|-----------|--------------|" >> "$outfile"

        get_data "${EXPORT_DIR}/firewall_zones.json" | jq -r '
            sort_by(.name) | .[] |
            "| \(.name // "—") | `\(.id[0:8])…` | \((.networkIds // []) | length) |"
        ' >> "$outfile" 2>/dev/null

        echo "" >> "$outfile"
    fi

    # ── Firewall Policies ──
    if [ -f "${EXPORT_DIR}/firewall_policies.json" ]; then
        local policy_count
        policy_count=$(get_count "${EXPORT_DIR}/firewall_policies.json")

        # ── User-Defined Policies ──
        echo "## User-Defined Policies" >> "$outfile"
        echo "" >> "$outfile"
        echo "| Index | Name | Action | Source Zone | Dest Zone | IP Version | State Filter | Return | Log | Enabled |" >> "$outfile"
        echo "|-------|------|--------|-----------|-----------|------------|-------------|--------|-----|---------|" >> "$outfile"

        get_data "${EXPORT_DIR}/firewall_policies.json" | jq -r '
            [ .[] | select(.metadata.origin == "USER_DEFINED") ] |
            sort_by(.index) | .[] |
            [
                (.index // 0 | tostring),
                (.name // "—"),
                (.action.type // "—"),
                (.source.zoneId // "any"),
                (.destination.zoneId // "any"),
                (.ipProtocolScope.ipVersion // "—"),
                ((.connectionStateFilter // []) | join(", ")),
                (if .action.allowReturnTraffic then "✅" else "—" end),
                (if .loggingEnabled then "✅" else "—" end),
                (if .enabled then "✅" else "❌" end)
            ] | @tsv
        ' 2>/dev/null | while IFS=$'\t' read -r idx name action src_zone dst_zone ip_ver state_filter return_traffic logging enabled; do
            local src_name dst_name
            src_name=$(resolve_zone "$src_zone")
            dst_name=$(resolve_zone "$dst_zone")
            [ -z "$state_filter" ] && state_filter="—"
            echo "| ${idx} | ${name} | ${action} | ${src_name} | ${dst_name} | ${ip_ver} | ${state_filter} | ${return_traffic} | ${logging} | ${enabled} |" >> "$outfile"
        done

        echo "" >> "$outfile"

        # ── User Policy Details ──
        echo "### User Policy Details" >> "$outfile"
        echo "" >> "$outfile"

        get_data "${EXPORT_DIR}/firewall_policies.json" | jq -c '
            [ .[] | select(.metadata.origin == "USER_DEFINED") ] |
            sort_by(.index) | .[]
        ' 2>/dev/null | while IFS= read -r policy_json; do
            local name action allow_return enabled idx ip_ver logging
            local src_zone_id dst_zone_id
            local state_filter

            name=$(echo "$policy_json" | jq -r '.name // "Unnamed"')
            action=$(echo "$policy_json" | jq -r '.action.type // "—"')
            allow_return=$(echo "$policy_json" | jq -r '.action.allowReturnTraffic // false')
            enabled=$(echo "$policy_json" | jq -r 'if .enabled then "true" else "false" end')
            idx=$(echo "$policy_json" | jq -r '.index // "—"')
            ip_ver=$(echo "$policy_json" | jq -r '.ipProtocolScope.ipVersion // "—"')
            logging=$(echo "$policy_json" | jq -r 'if .loggingEnabled then "true" else "false" end')
            state_filter=$(echo "$policy_json" | jq -r '(.connectionStateFilter // []) | join(", ")')

            src_zone_id=$(echo "$policy_json" | jq -r '.source.zoneId // "any"')
            dst_zone_id=$(echo "$policy_json" | jq -r '.destination.zoneId // "any"')
            local src_zone_name dst_zone_name
            src_zone_name=$(resolve_zone "$src_zone_id")
            dst_zone_name=$(resolve_zone "$dst_zone_id")

            # Source traffic filter details
            local src_filter_type src_ip_filter_type src_traffic_list src_port_list src_net_ids src_match_opposite
            src_filter_type=$(echo "$policy_json" | jq -r '.source.trafficFilter.type // "none"')
            src_ip_filter_type=$(echo "$policy_json" | jq -r '.source.trafficFilter.ipAddressFilter.type // empty')
            src_traffic_list=$(echo "$policy_json" | jq -r '.source.trafficFilter.ipAddressFilter.trafficMatchingListId // empty')
            src_match_opposite=$(echo "$policy_json" | jq -r '.source.trafficFilter.ipAddressFilter.matchOpposite // empty')
            src_port_list=$(echo "$policy_json" | jq -r '.source.trafficFilter.portFilter.trafficMatchingListId // empty')
            src_net_ids=$(echo "$policy_json" | jq -r '(.source.trafficFilter.networkFilter.networkIds // []) | join(", ")')

            # Destination traffic filter details
            local dst_filter_type dst_ip_filter_type dst_traffic_list dst_port_list dst_net_ids dst_match_opposite
            dst_filter_type=$(echo "$policy_json" | jq -r '.destination.trafficFilter.type // "none"')
            dst_ip_filter_type=$(echo "$policy_json" | jq -r '.destination.trafficFilter.ipAddressFilter.type // empty')
            dst_traffic_list=$(echo "$policy_json" | jq -r '.destination.trafficFilter.ipAddressFilter.trafficMatchingListId // empty')
            dst_match_opposite=$(echo "$policy_json" | jq -r '.destination.trafficFilter.ipAddressFilter.matchOpposite // empty')
            dst_port_list=$(echo "$policy_json" | jq -r '.destination.trafficFilter.portFilter.trafficMatchingListId // empty')
            dst_net_ids=$(echo "$policy_json" | jq -r '(.destination.trafficFilter.networkFilter.networkIds // []) | join(", ")')

            {
                echo "#### ${name}"
                echo "- **Index:** ${idx}"
                echo "- **Action:** ${action}"
                echo "- **Allow Return Traffic:** ${allow_return}"
                echo "- **Enabled:** ${enabled}"
                echo "- **IP Version:** ${ip_ver}"
                echo "- **Logging:** ${logging}"
                [ -n "$state_filter" ] && echo "- **Connection State Filter:** ${state_filter}"
                echo ""
                echo "**Source:**"
                echo "- Zone: **${src_zone_name}** (\`${src_zone_id:0:12}…\`)"
                if [ "$src_filter_type" != "none" ]; then
                    echo "- Filter Type: ${src_filter_type}"
                    [ -n "$src_ip_filter_type" ] && echo "  - IP Filter: ${src_ip_filter_type}"
                    [ -n "$src_traffic_list" ] && echo "  - Matching List: \`${src_traffic_list}\`"
                    [ "$src_match_opposite" = "true" ] && echo "  - Match Opposite: yes (negated)"
                    [ -n "$src_port_list" ] && echo "  - Port Matching List: \`${src_port_list}\`"
                    if [ -n "$src_net_ids" ]; then
                        echo -n "  - Networks: "
                        local first=true
                        for nid in $(echo "$src_net_ids" | tr ',' ' '); do
                            nid=$(echo "$nid" | xargs)
                            local resolved
                            resolved=$(resolve_network "$nid")
                            if [ "$first" = true ]; then
                                echo -n "${resolved}"
                                first=false
                            else
                                echo -n ", ${resolved}"
                            fi
                        done
                        echo ""
                    fi
                fi
                echo ""
                echo "**Destination:**"
                echo "- Zone: **${dst_zone_name}** (\`${dst_zone_id:0:12}…\`)"
                if [ "$dst_filter_type" != "none" ]; then
                    echo "- Filter Type: ${dst_filter_type}"
                    [ -n "$dst_ip_filter_type" ] && echo "  - IP Filter: ${dst_ip_filter_type}"
                    [ -n "$dst_traffic_list" ] && echo "  - Matching List: \`${dst_traffic_list}\`"
                    [ "$dst_match_opposite" = "true" ] && echo "  - Match Opposite: yes (negated)"
                    [ -n "$dst_port_list" ] && echo "  - Port Matching List: \`${dst_port_list}\`"
                    if [ -n "$dst_net_ids" ]; then
                        echo -n "  - Networks: "
                        local first=true
                        for nid in $(echo "$dst_net_ids" | tr ',' ' '); do
                            nid=$(echo "$nid" | xargs)
                            local resolved
                            resolved=$(resolve_network "$nid")
                            if [ "$first" = true ]; then
                                echo -n "${resolved}"
                                first=false
                            else
                                echo -n ", ${resolved}"
                            fi
                        done
                        echo ""
                    fi
                fi
                echo ""
                echo "- **Policy ID:** \`$(echo "$policy_json" | jq -r '.id // "—"')\`"
                echo ""
                echo "---"
                echo ""
            } >> "$outfile"
        done

        # ── System-Defined Policies ──
        echo "## System-Defined Policies" >> "$outfile"
        echo "" >> "$outfile"
        echo "> Auto-generated by UniFi based on zone configuration. These form the default zone-to-zone matrix." >> "$outfile"
        echo "" >> "$outfile"
        echo "| Source Zone | Dest Zone | Action | State Filter | IP Version | Logging | Index |" >> "$outfile"
        echo "|-----------|-----------|--------|-------------|------------|---------|-------|" >> "$outfile"

        get_data "${EXPORT_DIR}/firewall_policies.json" | jq -r '
            [ .[] | select(.metadata.origin == "SYSTEM_DEFINED") ] |
            sort_by(.source.zoneId, .destination.zoneId, .index) | .[] |
            [
                (.source.zoneId // "any"),
                (.destination.zoneId // "any"),
                (.action.type // "—"),
                ((.connectionStateFilter // []) | join(", ")),
                (.ipProtocolScope.ipVersion // "—"),
                (if .loggingEnabled then "✅" else "—" end),
                (.index // 0 | tostring)
            ] | @tsv
        ' 2>/dev/null | while IFS=$'\t' read -r src_zone dst_zone action state_filter ip_ver logging idx; do
            local src_name dst_name
            src_name=$(resolve_zone "$src_zone")
            dst_name=$(resolve_zone "$dst_zone")
            [ -z "$state_filter" ] && state_filter="—"
            local display_idx="$idx"
            [ "$idx" = "2147483647" ] && display_idx="MAX (default)"
            echo "| ${src_name} | ${dst_name} | ${action} | ${state_filter} | ${ip_ver} | ${logging} | ${display_idx} |" >> "$outfile"
        done

        echo "" >> "$outfile"

        # ── Stats ──
        local user_count sys_count enabled_count disabled_count
        user_count=$(get_data "${EXPORT_DIR}/firewall_policies.json" | jq '[.[] | select(.metadata.origin == "USER_DEFINED")] | length' 2>/dev/null || echo "?")
        sys_count=$(get_data "${EXPORT_DIR}/firewall_policies.json" | jq '[.[] | select(.metadata.origin == "SYSTEM_DEFINED")] | length' 2>/dev/null || echo "?")
        enabled_count=$(get_data "${EXPORT_DIR}/firewall_policies.json" | jq '[.[] | select(.enabled == true)] | length' 2>/dev/null || echo "?")
        disabled_count=$(get_data "${EXPORT_DIR}/firewall_policies.json" | jq '[.[] | select(.enabled == false)] | length' 2>/dev/null || echo "?")

        {
            echo "## Policy Statistics"
            echo ""
            echo "- **Total Policies:** ${policy_count}"
            echo "- **User-Defined:** ${user_count}"
            echo "- **System-Defined:** ${sys_count}"
            echo "- **Enabled:** ${enabled_count}"
            echo "- **Disabled:** ${disabled_count}"
            echo ""
        } >> "$outfile"

        log_info "Policies: ${policy_count} total (${user_count} user, ${sys_count} system)"
    else
        echo "## Firewall Policies" >> "$outfile"
        echo "" >> "$outfile"
        echo "> ⚠️ firewall_policies.json not found — run \`unifi-api-toolkit.sh all\`" >> "$outfile"
        echo "" >> "$outfile"
        log_warn "firewall_policies.json not found"
    fi

    # ── Traffic Matching Lists placeholder ──
    cat >> "$outfile" << 'GROUPS'
## Traffic Matching Lists / Firewall Groups

> Policies above reference traffic matching list UUIDs.
> Export details: `unifi-api-toolkit.sh raw firewall/groups`
> Or view in UI: Network → Settings → Profiles → IP Groups / Port Groups
>
> TODO: Document your firewall groups here

| Group Name | Type | UUID (short) | Members | Used By |
|-----------|------|-------------|---------|---------|
| <!-- fill in --> | <!-- IP/Port --> | <!-- UUID --> | <!-- members --> | <!-- which policies --> |

## Audit Notes

| Date | Reviewed By | Findings | Actions Taken |
|------|------------|----------|---------------|
| <!-- date --> | <!-- name --> | <!-- findings --> | <!-- actions --> |

GROUPS

    log_info "Saved: ${outfile}"
}

generate_clients() {
    if [ ! -f "${EXPORT_DIR}/clients.json" ]; then
        return
    fi

    local client_count
    client_count=$(get_count "${EXPORT_DIR}/clients.json")
    [ "$client_count" -eq 0 ] && return

    local outfile="${DIR_DEVICES}/clients.md"

    log_section "Generating devices/clients.md"

    cat > "$outfile" << EOF
# Connected Clients

> Auto-generated from UniFi API export on ${DATE_SHORT}
> Clients: ${client_count}
> **Note:** Snapshot at export time, not a complete inventory.

## Client Summary

| Name | MAC | IP | Type | Network | Connected To |
|------|-----|-----|------|---------|-------------|
EOF

    # Handle both Integration API v1 field names and possible variations
    get_data "${EXPORT_DIR}/clients.json" | jq -r '
        sort_by(.name // .hostname // .displayName // .macAddress // "") | .[] |
        "| \(.name // .hostname // .displayName // "—") | \(.macAddress // .mac // "—") | \(.ipAddress // .ip // "—") | \(.type // "—") | \(.networkId // .network_id // "—") | \(.uplinkDeviceName // .connectedDevice // "—") |"
    ' >> "$outfile" 2>/dev/null

    echo "" >> "$outfile"

    local wired wireless
    wired=$(get_data "${EXPORT_DIR}/clients.json" | jq '[.[] | select(.type == "WIRED" or .type == "wired")] | length' 2>/dev/null || echo "?")
    wireless=$(get_data "${EXPORT_DIR}/clients.json" | jq '[.[] | select(.type == "WIRELESS" or .type == "wireless")] | length' 2>/dev/null || echo "?")

    {
        echo "## Statistics"
        echo ""
        echo "- **Total:** ${client_count}"
        echo "- **Wired:** ${wired}"
        echo "- **Wireless:** ${wireless}"
        echo ""
    } >> "$outfile"

    log_info "Saved: ${outfile} (${client_count} clients)"
}

generate_port_forwarding() {
    if [ ! -f "${EXPORT_DIR}/port-forwarding.json" ]; then
        return
    fi

    local count
    count=$(get_count "${EXPORT_DIR}/port-forwarding.json")
    [ "$count" -eq 0 ] && return

    local outfile="${DIR_SECURITY}/port_forwarding.md"

    log_section "Generating security/port_forwarding.md"

    cat > "$outfile" << EOF
# Port Forwarding Rules

> Auto-generated from UniFi API export on ${DATE_SHORT}
> ⚠️ **Security Note:** Every port forward is an attack surface. Prefer VPN or Cloudflare Tunnel.

| Name | Protocol | Source | WAN Port | Dest IP | Dest Port | Enabled |
|------|----------|--------|----------|---------|-----------|---------|
EOF

    get_data "${EXPORT_DIR}/port-forwarding.json" | jq -r '
        .[] |
        "| \(.name // "—") | \(.protocol // "—") | \(.source // "any") | \(.externalPort // .wanPort // .srcPort // "—") | \(.forwardIp // .lanIp // .destIp // "—") | \(.forwardPort // .lanPort // .destPort // "—") | \(if .enabled // true then "✅" else "❌" end) |"
    ' >> "$outfile" 2>/dev/null

    echo "" >> "$outfile"

    log_info "Saved: ${outfile} (${count} rules)"
}

generate_change_log_entry() {
    local outfile="${DIR_OPERATIONS}/change_log.md"

    log_section "Generating operations/change_log.md"

    local source_host export_date
    source_host=$(get_source_host)
    export_date=$(get_export_date)

    local file_list=""
    local total_records=0
    for f in "${EXPORT_DIR}"/*.json; do
        [ ! -f "$f" ] && continue
        local fname count
        fname=$(basename "$f")
        count=$(get_count "$f")
        file_list="${file_list}\n  - ${fname}: ${count} records"
        total_records=$((total_records + count))
    done

    if [ -f "$outfile" ]; then
        local tmpfile
        tmpfile=$(mktemp)
        {
            head -5 "$outfile"
            echo ""
            echo "## ${DATE_SHORT} — Documentation Generated from API Export"
            echo "**Change:** Auto-generated documentation from UniFi API export"
            echo "**Source:** ${source_host} | Export: ${export_date}"
            echo "**Records:** ${total_records} total"
            echo "**Source files:**"
            echo -e "$file_list"
            echo ""
            echo "**Outcome:** Review and supplement with manual details"
            echo ""
            echo "---"
            echo ""
            tail -n +6 "$outfile"
        } > "$tmpfile"
        mv "$tmpfile" "$outfile"
        log_info "Prepended entry to: ${outfile}"
    else
        cat > "$outfile" << EOF
# Network Change Log

> Track all network configuration changes for audit trail and troubleshooting.

---

## ${DATE_SHORT} — Documentation Generated from API Export
**Change:** Auto-generated documentation from UniFi API export
**Source:** ${source_host} | Export: ${export_date}
**Records:** ${total_records} total
**Source files:**
$(echo -e "$file_list")

**Outcome:** Review and supplement with manual details

---

## YYYY-MM-DD — [Change Title]
**Change:** [What changed]
**Reason:** [Why]
**Impact:** [Who/what affected]
**Outcome:** [Success/issues/rollback]
**Documents Updated:** [Which docs were updated]

EOF
        log_info "Created: ${outfile}"
    fi
}

generate_consistency_report() {
    local outfile="${DIR_OPERATIONS}/_CONSISTENCY_CHECK.md"

    log_section "Running Consistency Checks"

    cat > "$outfile" << EOF
# Documentation Consistency Check

> Generated: ${DATE_NOW}

EOF

    local issues=0

    # Check: Firewall policies reference valid zones
    if [ -f "${EXPORT_DIR}/firewall_policies.json" ] && [ -f "${EXPORT_DIR}/firewall_zones.json" ]; then
        local known_zones
        known_zones=$(get_data "${EXPORT_DIR}/firewall_zones.json" | jq -r '.[].id' 2>/dev/null | sort -u)

        local policy_zones
        policy_zones=$(get_data "${EXPORT_DIR}/firewall_policies.json" | jq -r '
            .[] | (.source.zoneId // empty), (.destination.zoneId // empty)
        ' 2>/dev/null | sort -u)

        local orphaned=""
        while IFS= read -r zid; do
            [ -z "$zid" ] && continue
            if ! echo "$known_zones" | grep -q "^${zid}$"; then
                local short_id="${zid:0:12}"
                orphaned="${orphaned}- Policy references zone \`${short_id}…\` not in firewall_zones.json\n"
                issues=$((issues + 1))
            fi
        done <<< "$policy_zones"

        if [ -n "$orphaned" ]; then
            echo "## ⚠️ Zone Reference Mismatches" >> "$outfile"
            echo "" >> "$outfile"
            echo -e "$orphaned" >> "$outfile"
            echo "" >> "$outfile"
        fi
    fi

    # Check: Network zoneIds match zones
    if [ -f "${EXPORT_DIR}/networks.json" ] && [ -f "${EXPORT_DIR}/firewall_zones.json" ]; then
        local known_zones
        known_zones=$(get_data "${EXPORT_DIR}/firewall_zones.json" | jq -r '.[].id' 2>/dev/null | sort -u)

        local orphaned=""
        while IFS= read -r zid; do
            [ -z "$zid" ] && continue
            if ! echo "$known_zones" | grep -q "^${zid}$"; then
                orphaned="${orphaned}- Network references zone \`${zid:0:12}…\` not in zones\n"
                issues=$((issues + 1))
            fi
        done < <(get_data "${EXPORT_DIR}/networks.json" | jq -r '.[].zoneId // empty' 2>/dev/null | sort -u)

        if [ -n "$orphaned" ]; then
            echo "## ⚠️ Network → Zone Mismatches" >> "$outfile"
            echo "" >> "$outfile"
            echo -e "$orphaned" >> "$outfile"
            echo "" >> "$outfile"
        fi
    fi

    # Check: Disabled user policies
    if [ -f "${EXPORT_DIR}/firewall_policies.json" ]; then
        local disabled_user
        disabled_user=$(get_data "${EXPORT_DIR}/firewall_policies.json" | jq -r '
            [.[] | select(.metadata.origin == "USER_DEFINED" and .enabled == false)] |
            if length > 0 then .[] | "- **\(.name)** (index \(.index))" else empty end
        ' 2>/dev/null)

        if [ -n "$disabled_user" ]; then
            echo "## ℹ️ Disabled User Policies" >> "$outfile"
            echo "" >> "$outfile"
            echo "> Review if these should be removed or re-enabled." >> "$outfile"
            echo "" >> "$outfile"
            echo "$disabled_user" >> "$outfile"
            echo "" >> "$outfile"
        fi
    fi

    # Check: Firmware updates
    if [ -f "${EXPORT_DIR}/devices.json" ]; then
        local updatable
        updatable=$(get_data "${EXPORT_DIR}/devices.json" | jq -r '
            [.[] | select(.firmwareUpdatable == true)] |
            if length > 0 then .[] | "- **\(.name // "unnamed")** (\(.model // "?")) — firmware \(.firmwareVersion // "?")" else empty end
        ' 2>/dev/null)

        if [ -n "$updatable" ]; then
            echo "## ⚠️ Firmware Updates Available" >> "$outfile"
            echo "" >> "$outfile"
            echo "$updatable" >> "$outfile"
            echo "" >> "$outfile"
            issues=$((issues + 1))
        fi
    fi

    if [ "$issues" -eq 0 ]; then
        echo "## ✅ No Issues Found" >> "$outfile"
        echo "" >> "$outfile"
    else
        echo "## Summary: ${issues} item(s) flagged" >> "$outfile"
        echo "" >> "$outfile"
    fi

    {
        echo "## Manual Checks Recommended"
        echo ""
        echo "- [ ] Subnets and gateways filled in (API doesn't export these)"
        echo "- [ ] DHCP ranges documented"
        echo "- [ ] Firewall group members documented"
        echo "- [ ] Non-UniFi devices added to equipment_list.md"
        echo "- [ ] Static IP assignments documented in network_topology.md"
        echo ""
    } >> "$outfile"

    log_info "Report: ${outfile}"
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    echo ""
    echo "UniFi JSON → Documentation Converter"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    log_info "Source: ${EXPORT_DIR}"
    log_info "Output: ${OUTPUT_DIR}"
    echo "         ├── infrastructure/  (topology, networking)"
    echo "         ├── devices/         (equipment, clients)"
    echo "         ├── security/        (firewall, port forwarding)"
    echo "         └── operations/      (change log, consistency)"

    echo ""
    echo "  Available JSON exports:"
    for f in "${EXPORT_DIR}"/*.json; do
        [ ! -f "$f" ] && continue
        local fname count
        fname=$(basename "$f")
        count=$(get_count "$f")
        printf "    %-35s %s records\n" "$fname" "$count"
    done
    echo ""

    build_lookups

    generate_network_topology
    generate_equipment_list
    generate_firewall_rules
    generate_clients
    generate_port_forwarding
    generate_change_log_entry
    generate_consistency_report

    log_section "Conversion Complete"
    echo ""
    echo "  Generated documentation:"
    for subdir in infrastructure devices security operations; do
        local dirpath="${OUTPUT_DIR}/${subdir}"
        [ ! -d "$dirpath" ] && continue
        for f in "${dirpath}"/*.md; do
            [ ! -f "$f" ] && continue
            local relpath size
            relpath="${subdir}/$(basename "$f")"
            size=$(wc -c < "$f" | xargs)
            printf "    %-45s %s bytes\n" "$relpath" "$size"
        done
    done

    echo ""
    log_info "Document mapping:"
    echo "    infrastructure/network_topology.md  →  <<network_topology.md>>"
    echo "    devices/equipment_list.md           →  <<equipment_list.md>>"
    echo "    devices/clients.md                  →  (supplementary reference)"
    echo "    security/firewall_rules.md          →  <<firewall_rules.md>>"
    echo "    security/port_forwarding.md         →  (supplementary reference)"
    echo "    operations/change_log.md            →  <<change_log.md>>"
    echo "    operations/_CONSISTENCY_CHECK.md    →  (audit report)"
    echo ""
    log_warn "Integration API limitations — fill manually: subnets, gateways, DHCP, WiFi passwords"
    log_info "Re-run after each export to keep docs in sync."
}

main
