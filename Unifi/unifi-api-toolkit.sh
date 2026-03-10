#!/bin/bash
###############################################################################
# UniFi Dream Machine API Toolkit (Integration API)
# Purpose: Export network configuration data for analysis and documentation
#
# Auth: X-API-KEY header with key from:
#   Network → Settings → Control Plane → Integrations
#
# Requirements:
#   - curl, jq installed
#   - Run from a machine on your Management VLAN (WSL works)
#   - .env file with UDM_HOST, UNIFI_API_KEY, and UNIFI_SITE_ID
#
# First run:  ./unifi-api-toolkit.sh setup
# Then:       ./unifi-api-toolkit.sh quick
#
# Changelog:
#   2026-02-26 — Initial version with export and sanitization
#   2026-03-09 — Added: docs, firewall commands; dedicated exports for
#                wlans, port-profiles, firewall groups/zones, routes;
#                comprehensive markdown doc generation from JSON exports
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Load .env if present ────────────────────────────────────────────────────
if [ -f "${SCRIPT_DIR}/.env" ]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
fi

# ─── Configuration ───────────────────────────────────────────────────────────
UDM_HOST="${UDM_HOST:-}"
UNIFI_API_KEY="${UNIFI_API_KEY:-}"
UNIFI_SITE_ID="${UNIFI_SITE_ID:-}"
OUTPUT_DIR="${OUTPUT_DIR:-./unifi-exports}"
DOCS_DIR="${DOCS_DIR:-./Documents}"
DATE_STAMP=$(date +%Y%m%d-%H%M%S)
DATE_HUMAN=$(date '+%Y-%m-%d %H:%M:%S %Z')

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Helper Functions ────────────────────────────────────────────────────────
log_info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

check_dependencies() {
    local missing=()
    for cmd in curl jq; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo "Install with: sudo apt install ${missing[*]}"
        exit 1
    fi
}

validate_config() {
    local missing=false
    if [ -z "$UDM_HOST" ]; then
        log_error "UDM_HOST not set"
        missing=true
    fi
    if [ -z "$UNIFI_API_KEY" ]; then
        log_error "UNIFI_API_KEY not set"
        missing=true
    fi
    if [ -z "$UNIFI_SITE_ID" ]; then
        log_error "UNIFI_SITE_ID not set"
        missing=true
    fi
    if [ "$missing" = true ]; then
        echo ""
        echo "Run setup first:  $0 setup"
        exit 1
    fi
}

# Check that export files exist for docs generation
require_exports() {
    local required=("$@")
    local missing=()
    for f in "${required[@]}"; do
        if [ ! -f "${OUTPUT_DIR}/${f}" ]; then
            missing+=("$f")
        fi
    done
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing export files: ${missing[*]}"
        echo "Run an export first: $(basename "$0") all"
        return 1
    fi
    return 0
}

# Safe jq extraction — returns fallback on error
jq_safe() {
    local file="$1"
    local filter="$2"
    local fallback="${3:-}"
    jq -r "$filter" "$file" 2>/dev/null || echo "$fallback"
}

# Extract data array from export file (handles both .data.data[] and .data[] formats)
jq_data() {
    local file="$1"
    local filter="${2:-.}"
    jq -r "(.data.data // .data // [])[] | ${filter}" "$file" 2>/dev/null
}

# Extract data array as whole object
jq_data_arr() {
    local file="$1"
    jq -c '(.data.data // .data // [])' "$file" 2>/dev/null
}

# Human-readable byte sizes
human_size() {
    local bytes="$1"
    if [ "$bytes" -ge 1073741824 ] 2>/dev/null; then
        echo "$(echo "scale=1; $bytes / 1073741824" | bc)G"
    elif [ "$bytes" -ge 1048576 ] 2>/dev/null; then
        echo "$(echo "scale=1; $bytes / 1048576" | bc)M"
    elif [ "$bytes" -ge 1024 ] 2>/dev/null; then
        echo "$(echo "scale=0; $bytes / 1024" | bc)K"
    else
        echo "${bytes}B"
    fi
}

# ─── API Functions ───────────────────────────────────────────────────────────

BASE_URL=""

set_base_url() {
    BASE_URL="https://${UDM_HOST}/proxy/network/integration/v1/sites/${UNIFI_SITE_ID}"
}

# Generic GET with pagination support
api_get() {
    local endpoint="$1"
    local description="${2:-$endpoint}"
    local url="${BASE_URL}/${endpoint}"

    local first_response
    first_response=$(curl -sk -w "\n%{http_code}" \
        -H "X-API-KEY: ${UNIFI_API_KEY}" \
        "$url" 2>/dev/null)

    local http_code
    http_code=$(echo "$first_response" | tail -1)
    local body
    body=$(echo "$first_response" | sed '$d')

    if [ "$http_code" = "401" ]; then
        log_error "Authentication failed (HTTP 401) — check API key"
        exit 1
    elif [ "$http_code" = "400" ]; then
        log_warn "Bad request for ${description} — endpoint may not exist"
        echo '{"data":[]}'
        return
    elif [ "$http_code" != "200" ]; then
        log_warn "HTTP ${http_code} for ${description}"
        echo '{"data":[]}'
        return
    fi

    local total_count
    total_count=$(echo "$body" | jq -r '.totalCount // 0' 2>/dev/null)
    local limit
    limit=$(echo "$body" | jq -r '.limit // 25' 2>/dev/null)
    local current_data
    current_data=$(echo "$body" | jq -c '.data // []' 2>/dev/null)

    if [ "$total_count" -gt "$limit" ] 2>/dev/null; then
        local offset="$limit"
        while [ "$offset" -lt "$total_count" ]; do
            local sep="?"
            [[ "$url" == *"?"* ]] && sep="&"
            local page_response
            page_response=$(curl -sk \
                -H "X-API-KEY: ${UNIFI_API_KEY}" \
                "${url}${sep}offset=${offset}&limit=${limit}" 2>/dev/null)
            local page_data
            page_data=$(echo "$page_response" | jq -c '.data // []' 2>/dev/null)
            current_data=$(jq -sc '.[0] + .[1]' <(echo "$current_data") <(echo "$page_data"))
            offset=$((offset + limit))
        done
    fi

    echo "{\"data\":${current_data},\"totalCount\":${total_count}}"
}

# Simple GET without pagination (for non-list endpoints)
api_get_raw() {
    local endpoint="$1"
    local description="${2:-$endpoint}"
    local url="${BASE_URL}/${endpoint}"

    local response
    response=$(curl -sk -w "\n%{http_code}" \
        -H "X-API-KEY: ${UNIFI_API_KEY}" \
        "$url" 2>/dev/null)

    local http_code
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" != "200" ]; then
        log_warn "HTTP ${http_code} for ${description}"
        echo '{}'
        return
    fi

    echo "$body"
}

api_test() {
    log_info "Testing API connection to ${UDM_HOST}..."
    set_base_url

    local response
    local http_code

    response=$(curl -sk -w "\n%{http_code}" \
        -H "X-API-KEY: ${UNIFI_API_KEY}" \
        "https://${UDM_HOST}/proxy/network/integration/v1/sites" 2>/dev/null)

    http_code=$(echo "$response" | tail -1)

    case "$http_code" in
        200) log_info "Connection successful — authenticated to UDM" ;;
        401) log_error "API key rejected (HTTP 401)." && exit 1 ;;
        000) log_error "Cannot reach ${UDM_HOST}." && exit 1 ;;
        *)   log_error "Unexpected response: HTTP ${http_code}" && exit 1 ;;
    esac
}

save_output() {
    local data="$1"
    local filename="$2"
    local description="$3"
    local filepath="${OUTPUT_DIR}/${filename}"

    jq -n \
        --arg desc "$description" \
        --arg date "$DATE_STAMP" \
        --arg host "$UDM_HOST" \
        --arg site "$UNIFI_SITE_ID" \
        --argjson data "$data" \
        '{
            _metadata: {
                description: $desc,
                exported: $date,
                source: $host,
                site_id: $site,
                note: "Review for sensitive data before sharing"
            },
            data: $data
        }' > "$filepath" 2>/dev/null || {
            echo "$data" > "$filepath"
            log_warn "Saved raw output for ${filename}"
        }

    log_info "Saved: ${filepath} ($(wc -c < "$filepath" | xargs) bytes)"
}

# ─── Export Commands ─────────────────────────────────────────────────────────

export_devices() {
    log_section "UniFi Devices"
    local devices
    devices=$(api_get "devices" "devices")
    save_output "$devices" "devices.json" "All adopted UniFi devices"
    local count
    count=$(echo "$devices" | jq '.data | length' 2>/dev/null || echo "?")
    log_info "Exported ${count} devices"
    echo "$devices" | jq -r '.data[] | "  \(.name // "unnamed") | \(.model // "?") | IP: \(.ip // "?")"' 2>/dev/null || true
}

export_clients() {
    log_section "Clients"
    local clients
    clients=$(api_get "clients" "clients")
    save_output "$clients" "clients.json" "Connected clients"
    local count
    count=$(echo "$clients" | jq '.data | length' 2>/dev/null || echo "?")
    log_info "Exported ${count} clients"
}

export_networks() {
    log_section "Networks"
    local networks
    networks=$(api_get "networks" "networks")
    save_output "$networks" "networks.json" "Network / VLAN configuration"
    local count
    count=$(echo "$networks" | jq '.data | length' 2>/dev/null || echo "?")
    log_info "Exported ${count} networks"
    echo "$networks" | jq -r '.data[] | "  \(.name // "unnamed") | VLAN: \(.vlan // "untagged") | Subnet: \(.subnet // "n/a")"' 2>/dev/null || true
}

export_firewall_policies() {
    log_section "Firewall Policies"
    local policies
    policies=$(api_get "firewall/policies" "firewall policies")
    save_output "$policies" "firewall_policies.json" "Firewall policies"
    local count
    count=$(echo "$policies" | jq '.data | length' 2>/dev/null || echo "?")
    log_info "Exported ${count} firewall policies"
}

export_firewall_rules() {
    log_section "Firewall Rules"
    local rules
    rules=$(api_get "firewall/rules" "firewall rules")
    save_output "$rules" "firewall_rules.json" "Firewall rules"
    local count
    count=$(echo "$rules" | jq '.data | length' 2>/dev/null || echo "?")
    log_info "Exported ${count} firewall rules"
}

export_firewall_groups() {
    log_section "Firewall Groups"
    local groups
    groups=$(api_get "firewall/groups" "firewall groups")
    local count
    count=$(echo "$groups" | jq '.data | length' 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ] 2>/dev/null; then
        save_output "$groups" "firewall_groups.json" "Firewall IP/port groups"
        log_info "Exported ${count} firewall groups"
    else
        log_info "Firewall groups endpoint empty or unavailable"
    fi
}

export_firewall_zones() {
    log_section "Firewall Zones"
    local zones
    zones=$(api_get "firewall/zones" "firewall zones")
    local count
    count=$(echo "$zones" | jq '.data | length' 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ] 2>/dev/null; then
        save_output "$zones" "firewall_zones.json" "Firewall zone definitions"
        log_info "Exported ${count} firewall zones"
    else
        log_info "Firewall zones endpoint empty or unavailable"
    fi
}

export_wlans() {
    log_section "Wireless Networks (SSIDs)"
    local wlans
    wlans=$(api_get "wlans" "wireless networks")
    local count
    count=$(echo "$wlans" | jq '.data | length' 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ] 2>/dev/null; then
        save_output "$wlans" "wlans.json" "Wireless network (SSID) configuration"
        log_info "Exported ${count} wireless networks"
        echo "$wlans" | jq -r '.data[] | "  \(.name // "unnamed") | Security: \(.security // "?") | VLAN: \(.vlan // "n/a")"' 2>/dev/null || true
    else
        log_info "WLANs endpoint empty or unavailable"
    fi
}

export_port_profiles() {
    log_section "Port Profiles"
    local profiles
    profiles=$(api_get "port-profiles" "port profiles")
    local count
    count=$(echo "$profiles" | jq '.data | length' 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ] 2>/dev/null; then
        save_output "$profiles" "port_profiles.json" "Switch port profile definitions"
        log_info "Exported ${count} port profiles"
    else
        log_info "Port profiles endpoint empty or unavailable"
    fi
}

export_routes() {
    log_section "Static Routes"
    local routes
    routes=$(api_get "routes" "routes")
    local count
    count=$(echo "$routes" | jq '.data | length' 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ] 2>/dev/null; then
        save_output "$routes" "routes.json" "Static route configuration"
        log_info "Exported ${count} routes"
    else
        log_info "Routes endpoint empty or unavailable"
    fi
}

export_port_forwarding() {
    log_section "Port Forwarding"
    local forwards
    forwards=$(api_get "port-forwarding" "port forwarding")
    local count
    count=$(echo "$forwards" | jq '.data | length' 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ] 2>/dev/null; then
        save_output "$forwards" "port_forwarding.json" "Port forwarding rules"
        log_info "Exported ${count} port forward rules"
    else
        log_info "No port forwards configured (expected for zero-trust)"
    fi
}

export_traffic_rules() {
    log_section "Traffic Rules"
    local rules
    rules=$(api_get "traffic-rules" "traffic rules")
    local count
    count=$(echo "$rules" | jq '.data | length' 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ] 2>/dev/null; then
        save_output "$rules" "traffic_rules.json" "Traffic management rules"
        log_info "Exported ${count} traffic rules"
    else
        log_info "Traffic rules endpoint empty or unavailable"
    fi
}

export_traffic_routes() {
    log_section "Traffic Routes"
    local routes
    routes=$(api_get "traffic-routes" "traffic routes")
    local count
    count=$(echo "$routes" | jq '.data | length' 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ] 2>/dev/null; then
        save_output "$routes" "traffic_routes.json" "Traffic route configuration"
        log_info "Exported ${count} traffic routes"
    else
        log_info "Traffic routes endpoint empty or unavailable"
    fi
}

export_vpn() {
    log_section "VPN Configuration"
    local vpn
    vpn=$(api_get "vpn" "VPN")
    local count
    count=$(echo "$vpn" | jq '.data | length' 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ] 2>/dev/null; then
        save_output "$vpn" "vpn.json" "VPN configuration"
        log_info "Exported ${count} VPN configs"
    else
        log_info "VPN endpoint empty or unavailable"
    fi
}

# ─── Endpoint Discovery ─────────────────────────────────────────────────────

discover_endpoints() {
    log_section "Discovering Available Endpoints"

    local endpoints=(
        "devices"
        "clients"
        "networks"
        "firewall/policies"
        "firewall/rules"
        "firewall/groups"
        "firewall/zones"
        "port-forwarding"
        "port-profiles"
        "wlans"
        "routes"
        "dns"
        "dhcp"
        "vpn"
        "traffic-rules"
        "traffic-routes"
        "radius/profiles"
        "radius/users"
        "system"
        "settings"
        "events"
        "alerts"
    )

    echo ""
    printf "  %-30s %s\n" "ENDPOINT" "STATUS"
    printf "  %-30s %s\n" "--------" "------"

    for ep in "${endpoints[@]}"; do
        local response
        response=$(curl -sk -w "%{http_code}" -o /dev/null \
            -H "X-API-KEY: ${UNIFI_API_KEY}" \
            "${BASE_URL}/${ep}" 2>/dev/null)

        local status
        case "$response" in
            200) status="${GREEN}OK${NC} ($(curl -sk -H "X-API-KEY: ${UNIFI_API_KEY}" "${BASE_URL}/${ep}" 2>/dev/null | jq '.totalCount // .data // "?" | if type == "array" then length else . end' 2>/dev/null) items)" ;;
            400) status="${YELLOW}BAD REQUEST${NC}" ;;
            401) status="${RED}UNAUTHORIZED${NC}" ;;
            404) status="${YELLOW}NOT FOUND${NC}" ;;
            *)   status="${RED}HTTP ${response}${NC}" ;;
        esac

        printf "  %-30s %b\n" "$ep" "$status"
    done

    echo ""
    log_info "Use working endpoints above to plan exports"
}

# ─── Sanitization (unchanged from original) ──────────────────────────────────

detect_sensitive_data() {
    local filepath="$1"
    local filename
    filename=$(basename "$filepath")
    local findings=()

    local all_strings
    all_strings=$(jq -r '.. | strings' "$filepath" 2>/dev/null)

    local pub_ips
    pub_ips=$(echo "$all_strings" | \
        grep -oP '\b(?!10\.)(?!172\.(1[6-9]|2[0-9]|3[01])\.)(?!192\.168\.)(?!127\.)(?!0\.0\.0\.0)(?!169\.254\.)(?!22[4-9]\.)(?!23[0-9]\.)(?!24[0-9]\.)(?!25[0-5]\.)(([0-9]{1,3}\.){3}[0-9]{1,3})\b' 2>/dev/null | \
        sort -u)
    local pub_ip_count
    pub_ip_count=$(echo "$pub_ips" | grep -c . 2>/dev/null || echo "0")
    [ "$pub_ip_count" -gt 0 ] && findings+=("wan_ip|Public/WAN IPs|Replace with 203.0.113.x (documentation range)|${pub_ip_count} unique")

    local mac_count
    mac_count=$(echo "$all_strings" | \
        grep -oiP '([0-9a-f]{2}:){5}[0-9a-f]{2}' 2>/dev/null | sort -u | grep -c . 2>/dev/null || echo "0")
    [ "$mac_count" -gt 0 ] && findings+=("mac|MAC Addresses|Replace with AA:BB:CC:xx:xx:xx|${mac_count} unique")

    case "$filename" in
        devices.json)
            local serial_count
            serial_count=$(jq '[.data.data[]? // .data[]? | .serial // empty] | length' "$filepath" 2>/dev/null || echo "0")
            [ "$serial_count" -gt 0 ] && findings+=("serial|Serial Numbers|Replace with REDACTED-xxxx|${serial_count} found")
            local name_count
            name_count=$(jq '[.data.data[]? // .data[]? | .name // empty] | length' "$filepath" 2>/dev/null || echo "0")
            [ "$name_count" -gt 0 ] && findings+=("devname|Device Names|Replace with device-1, device-2...|${name_count} found")
            ;;
        clients.json)
            local hostname_count
            hostname_count=$(jq '[.data.data[]? // .data[]? | .hostname // .name // empty] | length' "$filepath" 2>/dev/null || echo "0")
            [ "$hostname_count" -gt 0 ] && findings+=("hostname|Hostnames / Names|Replace with host-1, host-2...|${hostname_count} found")
            local cname_count
            cname_count=$(jq '[.data.data[]? // .data[]? | .displayName // .display_name // empty] | length' "$filepath" 2>/dev/null || echo "0")
            [ "$cname_count" -gt 0 ] && findings+=("clientname|Client Display Names|Replace with client-1, client-2...|${cname_count} found")
            ;;
        wlans.json|wireless.json)
            local ssid_count
            ssid_count=$(jq '[.data.data[]? // .data[]? | .name // .ssid // empty] | length' "$filepath" 2>/dev/null || echo "0")
            [ "$ssid_count" -gt 0 ] && findings+=("ssid|SSID Names|Replace with WiFi-1, WiFi-2...|${ssid_count} found")
            local pass_count
            pass_count=$(jq '[.data.data[]? // .data[]? | .x_passphrase // .password // empty | select(. != "REDACTED")] | length' "$filepath" 2>/dev/null || echo "0")
            [ "$pass_count" -gt 0 ] && findings+=("password|WiFi Passwords|Replace with REDACTED|${pass_count} found")
            ;;
    esac

    printf '%s\n' "${findings[@]}"
}

apply_sanitization() {
    local filepath="$1"
    local output_path="$2"
    shift 2
    local categories=("$@")

    local tmpfile
    tmpfile=$(mktemp)
    cp "$filepath" "$tmpfile"

    for category in "${categories[@]}"; do
        case "$category" in
            wan_ip)
                local pub_ips
                pub_ips=$(jq -r '.. | strings' "$tmpfile" 2>/dev/null | \
                    grep -oP '\b(?!10\.)(?!172\.(1[6-9]|2[0-9]|3[01])\.)(?!192\.168\.)(?!127\.)(?!0\.0\.0\.0)(?!169\.254\.)(?!22[4-9]\.)(?!23[0-9]\.)(?!24[0-9]\.)(?!25[0-5]\.)(([0-9]{1,3}\.){3}[0-9]{1,3})\b' 2>/dev/null | \
                    sort -u)
                local counter=0
                while IFS= read -r ip; do
                    [ -z "$ip" ] && continue
                    counter=$((counter + 1))
                    local replacement="203.0.113.${counter}"
                    local escaped_ip="${ip//./\\.}"
                    sed -i "s/${escaped_ip}/${replacement}/g" "$tmpfile"
                done <<< "$pub_ips"
                ;;
            mac)
                local macs
                macs=$(jq -r '.. | strings' "$tmpfile" 2>/dev/null | \
                    grep -oiP '([0-9a-f]{2}:){5}[0-9a-f]{2}' 2>/dev/null | \
                    tr '[:upper:]' '[:lower:]' | sort -u)
                local counter=0
                while IFS= read -r mac; do
                    [ -z "$mac" ] && continue
                    counter=$((counter + 1))
                    local replacement
                    replacement=$(printf 'AA:BB:CC:00:%02X:%02X' $((counter / 256)) $((counter % 256)))
                    local mac_upper="${mac^^}"
                    sed -i "s/${mac}/${replacement}/g; s/${mac_upper}/${replacement}/g" "$tmpfile"
                done <<< "$macs"
                ;;
            serial)
                jq '(.data.data // .data // []) |= [to_entries[] | .value |=
                    (if .serial then .serial = "REDACTED-\((.serial | length) as $l | .serial[($l-4):])}"
                    else . end) | .value]' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
            devname)
                jq '(.data.data // .data // []) |= [to_entries[] |
                    .value.name = "device-\(.key + 1)" | .value]' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
            hostname)
                jq '(.data.data // .data // []) |= [to_entries[] | .value |=
                    (if .hostname then .hostname = "host-\(.key + 1)" else . end |
                     if .name then .name = "host-\(.key + 1)" else . end) | .value]' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
            clientname)
                jq '(.data.data // .data // []) |= [to_entries[] | .value |=
                    (if .displayName then .displayName = "client-\(.key + 1)" else . end |
                     if .display_name then .display_name = "client-\(.key + 1)" else . end) | .value]' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
            ssid)
                jq '(.data.data // .data // []) |= [to_entries[] | .value |=
                    (if .name then .name = "WiFi-\(.key + 1)" else . end |
                     if .ssid then .ssid = "WiFi-\(.key + 1)" else . end) | .value]' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
            password)
                jq '(.data.data // .data // []) |= map(
                    if .x_passphrase then .x_passphrase = "REDACTED" else . end |
                    if .password then .password = "REDACTED" else . end
                )' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
        esac
    done

    local cat_list
    cat_list=$(IFS=', '; echo "${categories[*]}")
    jq --arg cats "$cat_list" --arg date "$(date -Iseconds)" \
        'if ._metadata then ._metadata.sanitized = $cats | ._metadata.sanitized_date = $date else . end' \
        "$tmpfile" > "${tmpfile}.final" 2>/dev/null && mv "${tmpfile}.final" "$output_path" || mv "$tmpfile" "$output_path"

    rm -f "$tmpfile" "${tmpfile}.new" "${tmpfile}.final" 2>/dev/null
}

cmd_sanitize() {
    local source_dir="${2:-${OUTPUT_DIR}}"

    if [ ! -d "$source_dir" ]; then
        log_error "Export directory not found: ${source_dir}"
        echo "Run an export first: $(basename "$0") quick"
        exit 1
    fi

    local json_files=()
    local file_names=()
    while IFS= read -r f; do
        json_files+=("$f")
        file_names+=("$(basename "$f")")
    done < <(find "$source_dir" -maxdepth 1 -name "*.json" -type f | sort)

    if [ ${#json_files[@]} -eq 0 ]; then
        log_error "No JSON files found in ${source_dir}"
        exit 1
    fi

    log_section "Sanitize Exported Data"
    echo ""
    log_info "Source directory: ${source_dir}"
    echo ""

    echo "  Available files:"
    for i in "${!json_files[@]}"; do
        local f="${json_files[$i]}"
        local count
        count=$(jq '.data.data // .data | if type == "array" then length else "?" end' "$f" 2>/dev/null || echo "?")
        printf "    ${CYAN}%2d${NC}) %-30s (%s records)\n" "$((i + 1))" "${file_names[$i]}" "$count"
    done

    echo ""
    read -rp "  Select files to sanitize (comma-separated numbers, 'all', or 'q' to quit): " file_selection
    [ "$file_selection" = "q" ] && exit 0

    local selected_indices=()
    if [ "$file_selection" = "all" ]; then
        for i in "${!json_files[@]}"; do selected_indices+=("$i"); done
    else
        IFS=',' read -ra selections <<< "$file_selection"
        for sel in "${selections[@]}"; do
            sel=$(echo "$sel" | tr -d ' ')
            if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#json_files[@]} ]; then
                selected_indices+=("$((sel - 1))")
            else
                log_warn "Ignoring invalid selection: ${sel}"
            fi
        done
    fi

    if [ ${#selected_indices[@]} -eq 0 ]; then
        log_error "No valid files selected"
        exit 1
    fi

    local sanitized_dir="${source_dir}/sanitized"
    mkdir -p "$sanitized_dir"

    local files_processed=0
    local summary_lines=()

    for idx in "${selected_indices[@]}"; do
        local filepath="${json_files[$idx]}"
        local filename="${file_names[$idx]}"

        log_section "Sanitizing: ${filename}"

        local findings
        findings=$(detect_sensitive_data "$filepath")

        if [ -z "$findings" ]; then
            log_info "No sensitive data detected — skipping"
            cp "$filepath" "${sanitized_dir}/${filename}"
            summary_lines+=("  ├── ${filename}  → copied as-is (nothing to sanitize)")
            continue
        fi

        echo ""
        echo "  Detected sensitive data:"
        local option_categories=()
        local option_num=1
        while IFS='|' read -r category label description count; do
            [ -z "$category" ] && continue
            option_categories+=("$category")
            printf "    ${CYAN}%d${NC}) %-25s → %-45s [%s]\n" "$option_num" "$label" "$description" "$count"
            option_num=$((option_num + 1))
        done <<< "$findings"

        printf "    ${CYAN}%d${NC}) %-25s → %s\n" "$option_num" "All of the above" "Apply all sanitizations"

        echo ""
        read -rp "  Select options (comma-separated numbers, or ${option_num} for all): " option_selection

        local selected_categories=()
        if [ "$option_selection" = "$option_num" ] || [ "$option_selection" = "all" ]; then
            selected_categories=("${option_categories[@]}")
        else
            IFS=',' read -ra opt_selections <<< "$option_selection"
            for opt in "${opt_selections[@]}"; do
                opt=$(echo "$opt" | tr -d ' ')
                if [[ "$opt" =~ ^[0-9]+$ ]] && [ "$opt" -ge 1 ] && [ "$opt" -lt "$option_num" ]; then
                    selected_categories+=("${option_categories[$((opt - 1))]}")
                fi
            done
        fi

        if [ ${#selected_categories[@]} -eq 0 ]; then
            log_warn "No sanitizations selected — copying as-is"
            cp "$filepath" "${sanitized_dir}/${filename}"
            summary_lines+=("  ├── ${filename}  → copied as-is (no options selected)")
            continue
        fi

        log_info "Applying: ${selected_categories[*]}"
        apply_sanitization "$filepath" "${sanitized_dir}/${filename}" "${selected_categories[@]}"

        local redacted_list
        redacted_list=$(IFS=', '; echo "${selected_categories[*]}")
        summary_lines+=("  ├── ${filename}  → ${redacted_list} redacted")
        files_processed=$((files_processed + 1))

        log_info "Saved: ${sanitized_dir}/${filename}"
    done

    for i in "${!json_files[@]}"; do
        local filename="${file_names[$i]}"
        if [ ! -f "${sanitized_dir}/${filename}" ]; then
            cp "${json_files[$i]}" "${sanitized_dir}/${filename}"
        fi
    done

    log_section "Sanitization Complete"
    echo ""
    echo "  Output: ${sanitized_dir}/"
    echo ""
    for line in "${summary_lines[@]}"; do echo -e "$line"; done
    echo ""
    log_info "Sanitized files are safe to share. Originals untouched."

    if [ "$files_processed" -gt 0 ]; then
        local map_file="${sanitized_dir}/SANITIZE_MAP.txt"
        echo "# Sanitization Mapping — DO NOT SHARE THIS FILE" > "$map_file"
        echo "# Generated: $(date)" >> "$map_file"
        echo "" >> "$map_file"
        for idx in "${selected_indices[@]}"; do
            local filename="${file_names[$idx]}"
            local orig="${json_files[$idx]}"
            local sani="${sanitized_dir}/${filename}"
            if [ -f "$sani" ] && ! diff -q "$orig" "$sani" > /dev/null 2>&1; then
                echo "=== ${filename} ===" >> "$map_file"
                diff --unified=0 <(jq -S '.' "$orig" 2>/dev/null) <(jq -S '.' "$sani" 2>/dev/null) 2>/dev/null | \
                    grep '^[-+]' | grep -v '^[-+][-+][-+]' >> "$map_file" || true
                echo "" >> "$map_file"
            fi
        done
        chmod 600 "$map_file"
        log_info "Mapping saved: ${map_file} (DO NOT share this file)"
    fi
}

sanitize_exports() {
    log_section "Sanitization Report"
    log_warn "Review before sharing:"
    echo ""
    echo "  MAY contain sensitive data:"
    echo "  ├── clients.json             → MACs, hostnames, IPs, device names"
    echo "  ├── wlans.json               → SSIDs, possibly passwords"
    echo "  └── devices.json             → Serial numbers, device names"
    echo ""
    echo "  Generally safe to share as-is:"
    echo "  ├── networks.json            → VLAN/subnet structure"
    echo "  ├── firewall_policies.json   → Firewall policy config"
    echo "  ├── firewall_rules.json      → Firewall rules"
    echo "  ├── firewall_groups.json     → IP/port groups"
    echo "  ├── firewall_zones.json      → Zone definitions"
    echo "  ├── port_profiles.json       → Switch port profiles"
    echo "  └── routes.json              → Static routes"
    echo ""
    log_info "Internal IPs (RFC1918) are fine to share."
    log_info "Run '$(basename "$0") sanitize' to interactively redact sensitive data."
}


###############################################################################
#                                                                             #
#   DOCS GENERATION ENGINE                                                    #
#                                                                             #
#   Converts exported JSON into structured markdown documentation.            #
#   Output maps to the Documents/ GitHub repo structure.                      #
#                                                                             #
###############################################################################

# ─── docs hardware — UniFi device inventory with topology ────────────────────

docs_hardware() {
    local out="${DOCS_DIR}/infrastructure/hardware_topology.md"
    local devices_file="${OUTPUT_DIR}/devices.json"

    if [ ! -f "$devices_file" ]; then
        log_warn "devices.json not found — run 'all' export first"
        return 1
    fi

    log_info "Generating hardware topology..."

    mkdir -p "$(dirname "$out")"

    cat > "$out" << 'HEADER'
# Hardware Topology

HEADER

    echo "> Auto-generated by unifi-api-toolkit.sh docs hardware on ${DATE_HUMAN}" >> "$out"
    echo "> Source: ${UDM_HOST} | Export: ${DATE_STAMP}" >> "$out"
    echo ">" >> "$out"
    echo "> ⚠️ Review and enrich after generation — the Integration API may omit some fields." >> "$out"
    echo "" >> "$out"

    # ── Device Inventory Table ──
    echo "## UniFi Device Inventory" >> "$out"
    echo "" >> "$out"
    echo "| Device Name | Model | IP | MAC | Firmware | State | Uptime |" >> "$out"
    echo "|-------------|-------|----|-----|----------|-------|--------|" >> "$out"

    jq -r '(.data.data // .data // []) | sort_by(.name // "zzz") | .[] |
        "| \(.name // "unnamed") | \(.model // "?") | \(.ip // "?") | \(.mac // "?") | \(.firmwareVersion // .version // "?") | \(.state // "?") | \(.uptimeSeconds // "?" | if type == "number" then (. / 86400 | floor | tostring) + "d" else . end) |"
    ' "$devices_file" >> "$out" 2>/dev/null

    echo "" >> "$out"

    # ── Device detail blocks ──
    echo "## Device Details" >> "$out"
    echo "" >> "$out"

    jq -r '(.data.data // .data // []) | sort_by(.name // "zzz") | .[] |
        "### \(.name // "unnamed")\n" +
        "| Property | Value |\n" +
        "|----------|-------|\n" +
        "| **Model** | \(.model // "?") |\n" +
        "| **ID** | \(.id // "?") |\n" +
        "| **MAC** | \(.mac // "?") |\n" +
        "| **IP** | \(.ip // "?") |\n" +
        "| **Firmware** | \(.firmwareVersion // .version // "?") |\n" +
        "| **State** | \(.state // "?") |\n" +
        "| **Features** | \((.features // []) | join(", ") | if . == "" then "none" else . end) |\n"
    ' "$devices_file" >> "$out" 2>/dev/null

    # ── Port information (if available) ──
    local has_ports
    has_ports=$(jq '(.data.data // .data // []) | map(select(.interfaces != null or .ports != null)) | length' "$devices_file" 2>/dev/null || echo "0")

    if [ "$has_ports" -gt 0 ] 2>/dev/null; then
        echo "## Switch Port Assignments" >> "$out"
        echo "" >> "$out"
        echo "> Port data extracted from device interfaces. Cross-reference with physical labels." >> "$out"
        echo "" >> "$out"

        jq -r '
            (.data.data // .data // [])[] |
            select(.interfaces != null or .ports != null) |
            .name as $dev |
            "### \($dev)\n" +
            "| Port | Name | Speed | PoE | Network/VLAN |\n" +
            "|------|------|-------|-----|-------------|\n" +
            (
                (.interfaces // .ports // [])[] |
                "| \(.name // .idx // "?") | \(.portName // .label // "-") | \(.speed // "-") | \(.poe // "-") | \(.networkId // .network // "-") |"
            ) + "\n"
        ' "$devices_file" >> "$out" 2>/dev/null || true
    fi

    # ── Connection topology ──
    echo "## Connection Topology" >> "$out"
    echo "" >> "$out"
    echo "> Uplink relationships between UniFi devices. Reconstruct from \`uplinkDeviceId\` field." >> "$out"
    echo "" >> "$out"

    local has_uplinks
    has_uplinks=$(jq '(.data.data // .data // []) | map(select(.uplinkDeviceId != null)) | length' "$devices_file" 2>/dev/null || echo "0")

    if [ "$has_uplinks" -gt 0 ] 2>/dev/null; then
        echo "| Device | Uplinks To | Via Port |" >> "$out"
        echo "|--------|-----------|----------|" >> "$out"

        # Build a name lookup, then map uplinks
        jq -r '
            (.data.data // .data // []) as $devs |
            ($devs | map({(.id): .name}) | add // {}) as $names |
            $devs[] |
            select(.uplinkDeviceId != null) |
            "| \(.name // "?") | \($names[.uplinkDeviceId] // .uplinkDeviceId) | \(.uplinkPort // "?") |"
        ' "$devices_file" >> "$out" 2>/dev/null || true
    else
        echo "_Uplink data not available from Integration API. Fill in manually from UniFi UI topology view._" >> "$out"
    fi

    echo "" >> "$out"

    # ── ASCII diagram placeholder ──
    echo "## Network Diagram" >> "$out"
    echo "" >> "$out"
    echo '```' >> "$out"

    # Try to generate a basic tree from device data
    echo "Internet" >> "$out"
    echo "    │" >> "$out"
    echo "    ▼" >> "$out"
    echo "[ ISP Modem ] ─── WAN" >> "$out"
    echo "    │" >> "$out"
    echo "    ▼" >> "$out"

    # Find the gateway device (usually the UDM)
    local gateway_name
    gateway_name=$(jq -r '(.data.data // .data // [])[] | select(.features != null) | select(.features | index("gateway") or index("router")) | .name // "UDM"' "$devices_file" 2>/dev/null | head -1)
    gateway_name="${gateway_name:-UDM Pro Max}"

    local gateway_model
    gateway_model=$(jq -r '(.data.data // .data // [])[] | select(.features != null) | select(.features | index("gateway") or index("router")) | .model // "?"' "$devices_file" 2>/dev/null | head -1)

    echo "[ ${gateway_name} ] ─── ${gateway_model}" >> "$out"
    echo "    │" >> "$out"

    # List child devices
    jq -r '
        (.data.data // .data // [])[] |
        select(.features == null or (.features | (index("gateway") or index("router")) | not)) |
        "    ├── \(.name // "unnamed") | \(.model // "?") | IP: \(.ip // "?")"
    ' "$devices_file" >> "$out" 2>/dev/null || true

    echo '```' >> "$out"
    echo "" >> "$out"
    echo "> ⚠️ This is a flat device list. Edit to show actual physical topology (which switch connects to which)." >> "$out"

    log_info "Generated: ${out}"
}

# ─── docs clients — Client inventory grouped by VLAN ─────────────────────────

docs_clients() {
    local out="${DOCS_DIR}/devices/client_inventory.md"
    local clients_file="${OUTPUT_DIR}/clients.json"
    local networks_file="${OUTPUT_DIR}/networks.json"

    if [ ! -f "$clients_file" ]; then
        log_warn "clients.json not found — run 'all' export first"
        return 1
    fi

    log_info "Generating client inventory..."

    mkdir -p "$(dirname "$out")"

    cat > "$out" << HEADER
# Client Inventory

> Auto-generated by unifi-api-toolkit.sh docs clients on ${DATE_HUMAN}
> Source: ${UDM_HOST} | Export: ${DATE_STAMP}
>
> This document lists all clients known to the UniFi controller.
> Use this to audit VLAN assignments, identify unknown devices, and maintain the HAIPs/Admin groups.

HEADER

    # Build network ID → name lookup
    local net_lookup='{}'
    if [ -f "$networks_file" ]; then
        net_lookup=$(jq -c '(.data.data // .data // []) | map({(.id): (.name + " (VLAN " + ((.vlan // "untagged") | tostring) + ")")}) | add // {}' "$networks_file" 2>/dev/null || echo '{}')
    fi

    # Summary stats
    local total_clients
    total_clients=$(jq '(.data.data // .data // []) | length' "$clients_file" 2>/dev/null || echo "0")
    local wired_count
    wired_count=$(jq '(.data.data // .data // []) | map(select(.type == "WIRED" or .connectionType == "WIRED")) | length' "$clients_file" 2>/dev/null || echo "?")
    local wireless_count
    wireless_count=$(jq '(.data.data // .data // []) | map(select(.type == "WIRELESS" or .connectionType == "WIRELESS")) | length' "$clients_file" 2>/dev/null || echo "?")

    echo "## Summary" >> "$out"
    echo "" >> "$out"
    echo "| Metric | Count |" >> "$out"
    echo "|--------|-------|" >> "$out"
    echo "| Total clients | ${total_clients} |" >> "$out"
    echo "| Wired | ${wired_count} |" >> "$out"
    echo "| Wireless | ${wireless_count} |" >> "$out"
    echo "" >> "$out"

    # Full client table sorted by network
    echo "## All Clients" >> "$out"
    echo "" >> "$out"
    echo "| Name | IP | MAC | Type | Network | Uplink Device |" >> "$out"
    echo "|------|----|-----|------|---------|--------------|" >> "$out"

    jq -r --argjson nets "$net_lookup" '
        (.data.data // .data // []) | sort_by(.networkId // "zzz") | .[] |
        "| \(.name // .hostname // .displayName // .display_name // "unknown") | \(.ip // "?") | \(.mac // "?") | \(.type // .connectionType // "?") | \($nets[.networkId] // .networkId // "?") | \(.uplinkDeviceName // .uplinkDeviceId // "-") |"
    ' "$clients_file" >> "$out" 2>/dev/null

    echo "" >> "$out"

    # Group by network
    echo "## Clients by Network" >> "$out"
    echo "" >> "$out"

    if [ -f "$networks_file" ]; then
        # Get unique network IDs from clients
        local net_ids
        net_ids=$(jq -r '(.data.data // .data // [])[] | .networkId // empty' "$clients_file" 2>/dev/null | sort -u)

        while IFS= read -r nid; do
            [ -z "$nid" ] && continue
            local net_name
            net_name=$(echo "$net_lookup" | jq -r --arg id "$nid" '.[$id] // $id' 2>/dev/null)

            echo "### ${net_name}" >> "$out"
            echo "" >> "$out"
            echo "| Name | IP | MAC | Type |" >> "$out"
            echo "|------|----|-----|------|" >> "$out"

            jq -r --arg nid "$nid" '
                (.data.data // .data // [])[] |
                select(.networkId == $nid) |
                "| \(.name // .hostname // .displayName // "unknown") | \(.ip // "?") | \(.mac // "?") | \(.type // .connectionType // "?") |"
            ' "$clients_file" >> "$out" 2>/dev/null

            echo "" >> "$out"
        done <<< "$net_ids"
    fi

    # Clients without network assignment
    local orphan_count
    orphan_count=$(jq '(.data.data // .data // []) | map(select(.networkId == null)) | length' "$clients_file" 2>/dev/null || echo "0")
    if [ "$orphan_count" -gt 0 ] 2>/dev/null; then
        echo "### Unassigned / Unknown Network" >> "$out"
        echo "" >> "$out"
        echo "| Name | IP | MAC | Type |" >> "$out"
        echo "|------|----|-----|------|" >> "$out"

        jq -r '
            (.data.data // .data // [])[] |
            select(.networkId == null) |
            "| \(.name // .hostname // .displayName // "unknown") | \(.ip // "?") | \(.mac // "?") | \(.type // .connectionType // "?") |"
        ' "$clients_file" >> "$out" 2>/dev/null

        echo "" >> "$out"
    fi

    log_info "Generated: ${out}"
}

# ─── docs networks — VLAN/network configuration ─────────────────────────────

docs_networks() {
    local out="${DOCS_DIR}/infrastructure/network_topology.md"
    local networks_file="${OUTPUT_DIR}/networks.json"
    local zones_file="${OUTPUT_DIR}/firewall_zones.json"

    if [ ! -f "$networks_file" ]; then
        log_warn "networks.json not found — run 'all' export first"
        return 1
    fi

    log_info "Generating network topology..."

    mkdir -p "$(dirname "$out")"

    cat > "$out" << HEADER
# Network Topology

> Auto-generated by unifi-api-toolkit.sh docs networks on ${DATE_HUMAN}
> Source: ${UDM_HOST} | Export: ${DATE_STAMP}
>
> ⚠️ The UniFi Integration API does not expose subnet, gateway, or DHCP configuration.
> DHCP ranges filled from UniFi UI manually. Update when VLAN config changes.

HEADER

    # ── VLAN Structure Table ──
    echo "## VLAN Structure" >> "$out"
    echo "" >> "$out"
    echo "| VLAN ID | Name | Zone | Subnet | Gateway | Origin | Default | Enabled |" >> "$out"
    echo "|---------|------|------|--------|---------|--------|---------|---------|" >> "$out"

    # Build zone lookup if available
    local zone_lookup='{}'
    if [ -f "$zones_file" ]; then
        # Map network IDs to zone names
        zone_lookup=$(jq -c '
            (.data.data // .data // []) |
            [.[] | .name as $zname | (.networkIds // [])[] | {(.): $zname}] |
            add // {}
        ' "$zones_file" 2>/dev/null || echo '{}')
    fi

    jq -r --argjson zones "$zone_lookup" '
        (.data.data // .data // []) | sort_by(.vlan // 0) | .[] |
        "| \(.vlan // "untagged") | \(.name // "unnamed") | \($zones[.id] // "?") | \(.subnet // "—") | \(.gateway // "—") | \(.origin // "?") | \(if .isDefault then "⭐" else "" end) | \(if .enabled != false then "✅" else "❌" end) |"
    ' "$networks_file" >> "$out" 2>/dev/null

    echo "" >> "$out"
    echo "> ⭐ = Default network" >> "$out"
    echo "> Subnet/Gateway may be blank — the Integration API often omits these. Fill from UniFi UI." >> "$out"
    echo "" >> "$out"

    # ── Firewall Zones ──
    if [ -f "$zones_file" ]; then
        echo "## Firewall Zones" >> "$out"
        echo "" >> "$out"
        echo "| Zone Name | Networks | Origin | Configurable |" >> "$out"
        echo "|-----------|----------|--------|-------------|" >> "$out"

        # Build network ID → name lookup
        local net_names
        net_names=$(jq -c '(.data.data // .data // []) | map({(.id): .name}) | add // {}' "$networks_file" 2>/dev/null || echo '{}')

        jq -r --argjson names "$net_names" '
            (.data.data // .data // []) | sort_by(.name) | .[] |
            (.networkIds // []) as $nids |
            [$nids[] | $names[.] // .] | join(", ") | if . == "" then "—" else . end | . as $nets |
            "| \(.name // "?") | \($nets) | \(.origin // "?") | \(.configurable // "?") |"
        ' "$zones_file" >> "$out" 2>/dev/null

        echo "" >> "$out"
    fi

    # ── Network Details ──
    echo "## Network Details" >> "$out"
    echo "" >> "$out"

    jq -r --argjson zones "$zone_lookup" '
        (.data.data // .data // []) | sort_by(.vlan // 0) | .[] |
        "### \(.name // "unnamed")\n" +
        "- **VLAN ID:** \(.vlan // "untagged")\n" +
        "- **Zone:** \($zones[.id] // "?")\n" +
        "- **Subnet:** \(.subnet // "—")\n" +
        "- **Gateway:** \(.gateway // "—")\n" +
        "- **Origin:** \(.origin // "?")\n" +
        "- **Network ID:** `\(.id // "?")`\n" +
        (if .dhcpEnabled != null then "- **DHCP:** \(if .dhcpEnabled then "Enabled" else "Disabled" end)\n" else "" end) +
        (if .dhcpStart != null then "- **DHCP Range:** \(.dhcpStart) – \(.dhcpEnd // "?")\n" else "" end) +
        (if .domainName != null then "- **Domain:** \(.domainName)\n" else "" end) +
        ""
    ' "$networks_file" >> "$out" 2>/dev/null

    echo "" >> "$out"

    # ── Placeholder sections for manual enrichment ──
    cat >> "$out" << 'FOOTER'
---

## Static IP Assignments

> Fill in from UniFi DHCP reservations and manual assignments.

### Management VLAN

| Device | IP | MAC | Purpose |
|--------|-----|-----|---------|
| | | | |

### Home VLAN

| Device | IP | MAC | Purpose |
|--------|-----|-----|---------|
| | | | |

---

## Inter-VLAN Routing Policy

> Reference `Documents/security/firewall_rules.md` for full rule details.

| Source Zone | Destination Zone | Policy | Notes |
|-------------|-----------------|--------|-------|
| | | | |
FOOTER

    log_info "Generated: ${out}"
}

# ─── docs firewall — Firewall rules, groups, zones ──────────────────────────

docs_firewall() {
    local out="${DOCS_DIR}/security/firewall_rules.md"
    local policies_file="${OUTPUT_DIR}/firewall_policies.json"
    local groups_file="${OUTPUT_DIR}/firewall_groups.json"
    local zones_file="${OUTPUT_DIR}/firewall_zones.json"
    local networks_file="${OUTPUT_DIR}/networks.json"

    if [ ! -f "$policies_file" ]; then
        log_warn "firewall_policies.json not found — run 'all' export first"
        return 1
    fi

    log_info "Generating firewall rules documentation..."

    mkdir -p "$(dirname "$out")"

    cat > "$out" << HEADER
# Firewall Rules

> Auto-generated by unifi-api-toolkit.sh docs firewall on ${DATE_HUMAN}
> Source: ${UDM_HOST} | Export: ${DATE_STAMP}
> **Post-generation:** Review zone/group mappings and add missing member details.

HEADER

    # ── Zone Reference ──
    if [ -f "$zones_file" ] && [ -f "$networks_file" ]; then
        echo "## Zone Reference" >> "$out"
        echo "" >> "$out"
        echo "| Zone | Network | VLAN | Subnet |" >> "$out"
        echo "|------|---------|------|--------|" >> "$out"

        local net_info
        net_info=$(jq -c '(.data.data // .data // []) | map({(.id): {name: .name, vlan: (.vlan // "—"), subnet: (.subnet // "—")}}) | add // {}' "$networks_file" 2>/dev/null || echo '{}')

        jq -r --argjson nets "$net_info" '
            (.data.data // .data // []) | sort_by(.name) | .[] |
            (.networkIds // [])[] as $nid |
            ($nets[$nid] // {name: "?", vlan: "?", subnet: "?"}) as $n |
            "| \(.name // "?") | \($n.name) | \($n.vlan) | \($n.subnet) |"
        ' "$zones_file" >> "$out" 2>/dev/null

        echo "" >> "$out"
    fi

    # ── Firewall Groups ──
    if [ -f "$groups_file" ]; then
        local group_count
        group_count=$(jq '(.data.data // .data // []) | length' "$groups_file" 2>/dev/null || echo "0")

        if [ "$group_count" -gt 0 ] 2>/dev/null; then
            echo "## Firewall Groups" >> "$out"
            echo "" >> "$out"

            echo "### IP Groups" >> "$out"
            echo "" >> "$out"
            echo "| Name | Members | Referenced By |" >> "$out"
            echo "|------|---------|---------------|" >> "$out"

            jq -r '
                (.data.data // .data // [])[] |
                select(.type == "IPv4" or .type == "IP" or .type == "address-group" or (.members // [] | length > 0 and ((.members[0] // "") | test("^[0-9]")))) |
                "| \(.name // "?") | \((.members // []) | join(", ") | if . == "" then "—" else . end) | (check active rules) |"
            ' "$groups_file" >> "$out" 2>/dev/null

            echo "" >> "$out"

            echo "### Port Groups" >> "$out"
            echo "" >> "$out"
            echo "| Name | Ports | Referenced By |" >> "$out"
            echo "|------|-------|---------------|" >> "$out"

            jq -r '
                (.data.data // .data // [])[] |
                select(.type == "port-group" or .type == "Port" or (.members // [] | length > 0 and ((.members[0] // "") | test("^[0-9]+$")))) |
                "| \(.name // "?") | \((.members // []) | join(", ") | if . == "" then "—" else . end) | (check active rules) |"
            ' "$groups_file" >> "$out" 2>/dev/null

            echo "" >> "$out"

            # If we can't distinguish types, dump all groups
            echo "### All Groups (Raw)" >> "$out"
            echo "" >> "$out"
            echo "| Name | Type | Members |" >> "$out"
            echo "|------|------|---------|" >> "$out"

            jq -r '
                (.data.data // .data // [])[] |
                "| \(.name // "?") | \(.type // "?") | \((.members // []) | join(", ") | if . == "" then "—" else . end) |"
            ' "$groups_file" >> "$out" 2>/dev/null

            echo "" >> "$out"
        fi
    fi

    # ── Firewall Policies (user-defined) ──
    local user_count
    user_count=$(jq '(.data.data // .data // []) | map(select(.origin != "SYSTEM_DEFINED" and .predefined != true)) | length' "$policies_file" 2>/dev/null || echo "0")
    local system_count
    system_count=$(jq '(.data.data // .data // []) | map(select(.origin == "SYSTEM_DEFINED" or .predefined == true)) | length' "$policies_file" 2>/dev/null || echo "0")

    echo "## User-Defined Policies (${user_count} rules)" >> "$out"
    echo "" >> "$out"

    echo "| # | Rule Name | Action | Source Zone | Dst Zone | Dst IP Group | Dst Port Group | Enabled | Return Traffic |" >> "$out"
    echo "|---|-----------|--------|------------|----------|-------------|---------------|---------|---------------|" >> "$out"

    jq -r '
        (.data.data // .data // []) |
        [to_entries[] | select(.value.origin != "SYSTEM_DEFINED" and .value.predefined != true)] |
        sort_by(.value.index // .key) | .[].value |
        "| \(.index // "?") | \(.name // .description // "unnamed") | \(.action // "?") | \(.sourceZone // .source // "?") | \(.destinationZone // .destination // "?") | \(.destinationIpGroup // .destinationAddress // "-") | \(.destinationPortGroup // .destinationPort // "-") | \(if .enabled != false then "✅" else "❌" end) | \(if .allowReturnTraffic == true then "✅" else "-" end) |"
    ' "$policies_file" >> "$out" 2>/dev/null

    echo "" >> "$out"

    # ── Full policy details ──
    echo "### Policy Details" >> "$out"
    echo "" >> "$out"

    jq -r '
        (.data.data // .data // []) |
        [to_entries[] | select(.value.origin != "SYSTEM_DEFINED" and .value.predefined != true)] |
        sort_by(.value.index // .key) | .[].value |
        "#### \(.name // .description // "unnamed")\n" +
        "| Property | Value |\n" +
        "|----------|-------|\n" +
        "| **Action** | \(.action // "?") |\n" +
        "| **Source Zone** | \(.sourceZone // .source // "?") |\n" +
        "| **Source IP Group** | \(.sourceIpGroup // .sourceAddress // "-") |\n" +
        "| **Source Port Group** | \(.sourcePortGroup // .sourcePort // "-") |\n" +
        "| **Destination Zone** | \(.destinationZone // .destination // "?") |\n" +
        "| **Destination IP Group** | \(.destinationIpGroup // .destinationAddress // "-") |\n" +
        "| **Destination Port Group** | \(.destinationPortGroup // .destinationPort // "-") |\n" +
        "| **Allow Return Traffic** | \(.allowReturnTraffic // false) |\n" +
        "| **Enabled** | \(.enabled // true) |\n" +
        "| **ID** | `\(.id // "?")` |\n" +
        ""
    ' "$policies_file" >> "$out" 2>/dev/null

    echo "" >> "$out"

    # ── System Policies summary ──
    echo "## System-Defined Policies (${system_count} rules)" >> "$out"
    echo "" >> "$out"
    echo "> System policies provide baseline zone isolation. Key defaults listed below." >> "$out"
    echo "" >> "$out"

    echo "| Source Zone | Dst Zone | Action | Description |" >> "$out"
    echo "|------------|----------|--------|-------------|" >> "$out"

    jq -r '
        (.data.data // .data // []) |
        map(select(.origin == "SYSTEM_DEFINED" or .predefined == true)) |
        sort_by(.sourceZone // .source // "zzz") | .[] |
        "| \(.sourceZone // .source // "?") | \(.destinationZone // .destination // "?") | \(.action // "?") | \(.name // .description // "-") |"
    ' "$policies_file" >> "$out" 2>/dev/null

    echo "" >> "$out"

    # ── Audit checklist ──
    cat >> "$out" << 'FOOTER'
---

## Audit Checklist

- [ ] All group members resolved and documented
- [ ] Zone-to-network mappings verified
- [ ] No stale/unused rules
- [ ] No stale/unused groups
- [ ] All DNS rules point to correct zone (Management)
- [ ] `vlan IPs` group includes ALL VLAN subnets
- [ ] Admin List contains correct device IPs
- [ ] HAIPs group audit (verify all 6 IPs current)
FOOTER

    log_info "Generated: ${out}"
}

# ─── docs wifi — Wireless network configuration ─────────────────────────────

docs_wifi() {
    local out="${DOCS_DIR}/infrastructure/wifi_config.md"
    local wlans_file="${OUTPUT_DIR}/wlans.json"
    local networks_file="${OUTPUT_DIR}/networks.json"

    if [ ! -f "$wlans_file" ]; then
        log_warn "wlans.json not found — run 'all' export first (or endpoint may be unavailable)"
        return 1
    fi

    local wlan_count
    wlan_count=$(jq '(.data.data // .data // []) | length' "$wlans_file" 2>/dev/null || echo "0")

    if [ "$wlan_count" -eq 0 ] 2>/dev/null; then
        log_warn "No WLAN data available — endpoint may not return data via Integration API"
        return 1
    fi

    log_info "Generating WiFi configuration..."

    mkdir -p "$(dirname "$out")"

    # Build network lookup
    local net_lookup='{}'
    if [ -f "$networks_file" ]; then
        net_lookup=$(jq -c '(.data.data // .data // []) | map({(.id): {name: .name, vlan: (.vlan // "untagged")}}) | add // {}' "$networks_file" 2>/dev/null || echo '{}')
    fi

    cat > "$out" << HEADER
# WiFi Configuration

> Auto-generated by unifi-api-toolkit.sh docs wifi on ${DATE_HUMAN}
> Source: ${UDM_HOST} | Export: ${DATE_STAMP}
>
> ⚠️ SSID count matters: 4 SSIDs is the practical ceiling before WiFi performance degrades.
> Current count: ${wlan_count}

HEADER

    echo "## SSID Summary" >> "$out"
    echo "" >> "$out"
    echo "| SSID Name | Security | Network/VLAN | Band | Enabled | Hidden |" >> "$out"
    echo "|-----------|----------|-------------|------|---------|--------|" >> "$out"

    jq -r --argjson nets "$net_lookup" '
        (.data.data // .data // [])[] |
        ($nets[.networkId // ""] // {name: "?", vlan: "?"}) as $net |
        "| \(.name // .ssid // "?") | \(.security // "?") | \($net.name) (VLAN \($net.vlan)) | \(.band // .wlanBand // "?") | \(if .enabled != false then "✅" else "❌" end) | \(if .hideSSID == true or .hidden == true then "Yes" else "No" end) |"
    ' "$wlans_file" >> "$out" 2>/dev/null

    echo "" >> "$out"

    # ── SSID Details ──
    echo "## SSID Details" >> "$out"
    echo "" >> "$out"

    jq -r --argjson nets "$net_lookup" '
        (.data.data // .data // [])[] |
        ($nets[.networkId // ""] // {name: "?", vlan: "?"}) as $net |
        "### \(.name // .ssid // "unnamed")\n" +
        "| Property | Value |\n" +
        "|----------|-------|\n" +
        "| **Security** | \(.security // "?") |\n" +
        "| **Network** | \($net.name) (VLAN \($net.vlan)) |\n" +
        "| **Band** | \(.band // .wlanBand // "?") |\n" +
        "| **Enabled** | \(.enabled // true) |\n" +
        "| **Hidden** | \(.hideSSID // .hidden // false) |\n" +
        (if .wpaMode != null then "| **WPA Mode** | \(.wpaMode) |\n" else "" end) +
        (if .pmf != null then "| **PMF** | \(.pmf) |\n" else "" end) +
        (if .macFilter != null then "| **MAC Filter** | \(.macFilter) |\n" else "" end) +
        "| **ID** | `\(.id // "?")` |\n" +
        ""
    ' "$wlans_file" >> "$out" 2>/dev/null

    echo "" >> "$out"
    echo "---" >> "$out"
    echo "" >> "$out"
    echo "> **SSID ceiling reminder:** Adding a 5th SSID degrades WiFi performance. Use client-level VLAN overrides (MAC-based) instead of new SSIDs where possible." >> "$out"

    log_info "Generated: ${out}"
}

# ─── docs port-profiles — Switch port profile configuration ──────────────────

docs_port_profiles() {
    local out="${DOCS_DIR}/infrastructure/port_profiles.md"
    local profiles_file="${OUTPUT_DIR}/port_profiles.json"
    local networks_file="${OUTPUT_DIR}/networks.json"

    if [ ! -f "$profiles_file" ]; then
        log_warn "port_profiles.json not found — run 'all' export first (or endpoint may be unavailable)"
        return 1
    fi

    local profile_count
    profile_count=$(jq '(.data.data // .data // []) | length' "$profiles_file" 2>/dev/null || echo "0")

    if [ "$profile_count" -eq 0 ] 2>/dev/null; then
        log_warn "No port profile data available"
        return 1
    fi

    log_info "Generating port profiles..."

    mkdir -p "$(dirname "$out")"

    local net_lookup='{}'
    if [ -f "$networks_file" ]; then
        net_lookup=$(jq -c '(.data.data // .data // []) | map({(.id): (.name + " (VLAN " + ((.vlan // "untagged") | tostring) + ")")}) | add // {}' "$networks_file" 2>/dev/null || echo '{}')
    fi

    cat > "$out" << HEADER
# Port Profiles

> Auto-generated by unifi-api-toolkit.sh docs port-profiles on ${DATE_HUMAN}
> Source: ${UDM_HOST} | Export: ${DATE_STAMP}
>
> Port profiles define what VLAN(s) a switch port carries.
> Assign profiles to physical switch ports via UniFi UI → Devices → [Switch] → Ports.

HEADER

    echo "## Profile Summary" >> "$out"
    echo "" >> "$out"
    echo "| Profile Name | Native Network | Tagged Networks | PoE | STP |" >> "$out"
    echo "|-------------|---------------|----------------|-----|-----|" >> "$out"

    jq -r --argjson nets "$net_lookup" '
        (.data.data // .data // [])[] |
        ($nets[.nativeNetworkId // ""] // "—") as $native |
        ([(.taggedNetworkIds // [])[] | $nets[.] // .] | join(", ") | if . == "" then "—" else . end) as $tagged |
        "| \(.name // "?") | \($native) | \($tagged) | \(.poeEnabled // "-") | \(.stpEnabled // "-") |"
    ' "$profiles_file" >> "$out" 2>/dev/null

    echo "" >> "$out"

    # Detailed profile blocks
    echo "## Profile Details" >> "$out"
    echo "" >> "$out"

    jq -r --argjson nets "$net_lookup" '
        (.data.data // .data // [])[] |
        ($nets[.nativeNetworkId // ""] // "—") as $native |
        "### \(.name // "unnamed")\n" +
        "| Property | Value |\n" +
        "|----------|-------|\n" +
        "| **Native Network** | \($native) |\n" +
        "| **Tagged Networks** | \([(.taggedNetworkIds // [])[] | $nets[.] // .] | join(", ") | if . == "" then "None" else . end) |\n" +
        (if .poeEnabled != null then "| **PoE** | \(.poeEnabled) |\n" else "" end) +
        (if .stpEnabled != null then "| **STP** | \(.stpEnabled) |\n" else "" end) +
        (if .speed != null then "| **Speed** | \(.speed) |\n" else "" end) +
        (if .isolation != null then "| **Port Isolation** | \(.isolation) |\n" else "" end) +
        "| **ID** | `\(.id // "?")` |\n" +
        ""
    ' "$profiles_file" >> "$out" 2>/dev/null

    log_info "Generated: ${out}"
}

# ─── docs all — Generate everything ─────────────────────────────────────────

docs_all() {
    log_section "Generating All Documentation"
    echo ""
    log_info "Output directory: ${DOCS_DIR}/"
    echo ""

    mkdir -p "${DOCS_DIR}/infrastructure"
    mkdir -p "${DOCS_DIR}/devices"
    mkdir -p "${DOCS_DIR}/security"
    mkdir -p "${DOCS_DIR}/operations"

    local generated=0
    local skipped=0

    for doc_func in docs_hardware docs_networks docs_firewall docs_wifi docs_clients docs_port_profiles; do
        if $doc_func 2>/dev/null; then
            generated=$((generated + 1))
        else
            skipped=$((skipped + 1))
        fi
    done

    echo ""
    log_section "Documentation Generation Complete"
    log_info "Generated: ${generated} documents"
    [ "$skipped" -gt 0 ] && log_warn "Skipped: ${skipped} (missing export data)"
    log_info "Output: ${DOCS_DIR}/"
    echo ""
    echo "  Generated files:"
    find "${DOCS_DIR}" -name "*.md" -newer "${OUTPUT_DIR}" -type f 2>/dev/null | sort | while read -r f; do
        echo "    ${f}"
    done
    # If the above doesn't find anything (timestamp issue), just list all .md files
    if [ "$(find "${DOCS_DIR}" -name "*.md" -newer "${OUTPUT_DIR}" -type f 2>/dev/null | wc -l)" -eq 0 ]; then
        find "${DOCS_DIR}" -name "*.md" -type f 2>/dev/null | sort | while read -r f; do
            echo "    ${f}"
        done
    fi
    echo ""
    log_info "Review generated docs and enrich with manual data (DHCP ranges, static IPs, etc.)"
    log_info "Then commit to your GitHub repository."
}

# ─── docs command router ─────────────────────────────────────────────────────

cmd_docs() {
    local subcmd="${1:-}"

    if [ -z "$subcmd" ]; then
        echo "Usage: $(basename "$0") docs <subcommand>"
        echo ""
        echo "Generates markdown documentation from exported JSON data."
        echo "Run an export first: $(basename "$0") all"
        echo ""
        echo "Subcommands:"
        echo "  all            Generate all documentation"
        echo "  hardware       UniFi device inventory and topology"
        echo "  networks       VLAN structure and network config"
        echo "  firewall       Firewall rules, groups, zones"
        echo "  wifi           Wireless network (SSID) config"
        echo "  clients        Client inventory grouped by VLAN"
        echo "  port-profiles  Switch port profile definitions"
        echo ""
        echo "Options:"
        echo "  --docs-dir <path>   Output directory (default: ./Documents)"
        echo "  --export-dir <path> Source JSON directory (default: ./unifi-exports)"
        echo ""
        echo "Examples:"
        echo "  $(basename "$0") docs all"
        echo "  $(basename "$0") docs firewall"
        echo "  $(basename "$0") docs hardware --docs-dir ./my-docs"
        exit 0
    fi

    # Parse optional flags
    shift
    while [ $# -gt 0 ]; do
        case "$1" in
            --docs-dir)   DOCS_DIR="$2"; shift 2 ;;
            --export-dir) OUTPUT_DIR="$2"; shift 2 ;;
            *)            shift ;;
        esac
    done

    case "$subcmd" in
        all)            docs_all ;;
        hardware)       docs_hardware ;;
        networks)       docs_networks ;;
        firewall)       docs_firewall ;;
        wifi)           docs_wifi ;;
        clients)        docs_clients ;;
        port-profiles)  docs_port_profiles ;;
        *)              log_error "Unknown docs subcommand: ${subcmd}" && exit 1 ;;
    esac
}

# ─── Firewall Analysis Command ──────────────────────────────────────────────

cmd_firewall() {
    local subcmd="${1:-summary}"

    validate_config
    mkdir -p "$OUTPUT_DIR"
    set_base_url

    case "$subcmd" in
        export)
            log_section "Firewall Full Export"
            api_test
            export_firewall_policies
            export_firewall_rules
            export_firewall_groups
            export_firewall_zones
            log_info "Firewall data exported. Run 'docs firewall' to generate markdown."
            ;;
        summary)
            log_section "Firewall Summary"
            api_test

            local policies
            policies=$(api_get "firewall/policies" "firewall policies")

            local user_rules
            user_rules=$(echo "$policies" | jq '(.data // []) | map(select(.origin != "SYSTEM_DEFINED" and .predefined != true)) | length' 2>/dev/null || echo "?")
            local system_rules
            system_rules=$(echo "$policies" | jq '(.data // []) | map(select(.origin == "SYSTEM_DEFINED" or .predefined == true)) | length' 2>/dev/null || echo "?")

            echo ""
            echo "  User-defined rules:   ${user_rules}"
            echo "  System-defined rules: ${system_rules}"
            echo ""

            echo "  User rules by action:"
            echo "$policies" | jq -r '
                (.data // []) |
                map(select(.origin != "SYSTEM_DEFINED" and .predefined != true)) |
                group_by(.action) | .[] |
                "    \(.[0].action // "?"): \(length)"
            ' 2>/dev/null || true

            echo ""
            echo "  User rules:"
            echo "$policies" | jq -r '
                (.data // []) |
                [to_entries[] | select(.value.origin != "SYSTEM_DEFINED" and .value.predefined != true)] |
                sort_by(.value.index // .key) | .[].value |
                "    [\(.action // "?")] \(.name // .description // "unnamed")  (\(.sourceZone // .source // "?") → \(.destinationZone // .destination // "?"))"
            ' 2>/dev/null || true

            echo ""
            ;;
        groups)
            log_section "Firewall Groups"
            api_test

            local groups
            groups=$(api_get "firewall/groups" "firewall groups")

            echo ""
            echo "$groups" | jq -r '
                (.data // [])[] |
                "  \(.name // "?")" +
                "  [\(.type // "?")]" +
                "  Members: \((.members // []) | join(", ") | if . == "" then "(empty)" else . end)"
            ' 2>/dev/null || log_warn "Could not parse firewall groups"
            echo ""
            ;;
        zones)
            log_section "Firewall Zones"
            api_test

            local zones
            zones=$(api_get "firewall/zones" "firewall zones")

            # Get network names for lookup
            local networks
            networks=$(api_get "networks" "networks")
            local net_names
            net_names=$(echo "$networks" | jq -c '(.data // []) | map({(.id): .name}) | add // {}' 2>/dev/null || echo '{}')

            echo ""
            echo "$zones" | jq -r --argjson names "$net_names" '
                (.data // [])[] |
                ([(.networkIds // [])[] | $names[.] // .] | join(", ") | if . == "" then "(none)" else . end) as $nets |
                "  \(.name // "?")  →  \($nets)  [\(.origin // "?")]"
            ' 2>/dev/null || log_warn "Could not parse firewall zones"
            echo ""
            ;;
        *)
            echo "Usage: $(basename "$0") firewall <subcommand>"
            echo ""
            echo "Subcommands:"
            echo "  summary   Quick overview of all firewall rules (default)"
            echo "  export    Export firewall policies, rules, groups, and zones"
            echo "  groups    List all firewall groups with members"
            echo "  zones     List all firewall zones with network mappings"
            exit 0
            ;;
    esac
}

# ─── Summary Generator ──────────────────────────────────────────────────────

generate_summary() {
    log_section "Generating Summary Report"

    local summary_file="${OUTPUT_DIR}/SUMMARY.md"

    cat > "$summary_file" << EOF
# UniFi Network Export Summary
> Exported: ${DATE_STAMP}
> Source: ${UDM_HOST}
> Site ID: ${UNIFI_SITE_ID}
> API: Integration v1

EOF

    # Networks
    if [ -f "${OUTPUT_DIR}/networks.json" ]; then
        echo "## Networks" >> "$summary_file"
        echo '```' >> "$summary_file"
        jq -r '(.data.data // .data // [])[] | "\(.name // "unnamed") | VLAN: \(.vlan // "untagged") | Subnet: \(.subnet // "n/a")"' \
            "${OUTPUT_DIR}/networks.json" >> "$summary_file" 2>/dev/null || echo "(parse error)" >> "$summary_file"
        echo '```' >> "$summary_file"
        echo "" >> "$summary_file"
    fi

    # Devices
    if [ -f "${OUTPUT_DIR}/devices.json" ]; then
        echo "## Devices" >> "$summary_file"
        echo '```' >> "$summary_file"
        jq -r '(.data.data // .data // [])[] | "\(.name // "unnamed") | \(.model // "?") | IP: \(.ip // "?")"' \
            "${OUTPUT_DIR}/devices.json" >> "$summary_file" 2>/dev/null || echo "(parse error)" >> "$summary_file"
        echo '```' >> "$summary_file"
        echo "" >> "$summary_file"
    fi

    # WLANs
    if [ -f "${OUTPUT_DIR}/wlans.json" ]; then
        local wlan_count
        wlan_count=$(jq '(.data.data // .data // []) | length' "${OUTPUT_DIR}/wlans.json" 2>/dev/null || echo "0")
        if [ "$wlan_count" -gt 0 ] 2>/dev/null; then
            echo "## Wireless Networks: ${wlan_count}" >> "$summary_file"
            echo '```' >> "$summary_file"
            jq -r '(.data.data // .data // [])[] | "\(.name // "unnamed") | Security: \(.security // "?")"' \
                "${OUTPUT_DIR}/wlans.json" >> "$summary_file" 2>/dev/null
            echo '```' >> "$summary_file"
            echo "" >> "$summary_file"
        fi
    fi

    # Firewall
    if [ -f "${OUTPUT_DIR}/firewall_policies.json" ]; then
        local fw_total
        fw_total=$(jq '(.data.data // .data // []) | length' "${OUTPUT_DIR}/firewall_policies.json" 2>/dev/null || echo "?")
        local fw_user
        fw_user=$(jq '(.data.data // .data // []) | map(select(.origin != "SYSTEM_DEFINED" and .predefined != true)) | length' "${OUTPUT_DIR}/firewall_policies.json" 2>/dev/null || echo "?")
        echo "## Firewall Policies: ${fw_total} total (${fw_user} user-defined)" >> "$summary_file"
        echo "" >> "$summary_file"
    fi

    # Firewall Groups
    if [ -f "${OUTPUT_DIR}/firewall_groups.json" ]; then
        local grp_count
        grp_count=$(jq '(.data.data // .data // []) | length' "${OUTPUT_DIR}/firewall_groups.json" 2>/dev/null || echo "0")
        [ "$grp_count" -gt 0 ] && echo "## Firewall Groups: ${grp_count}" >> "$summary_file" && echo "" >> "$summary_file"
    fi

    # Clients
    if [ -f "${OUTPUT_DIR}/clients.json" ]; then
        local client_count
        client_count=$(jq '(.data.data // .data // []) | length' "${OUTPUT_DIR}/clients.json" 2>/dev/null || echo "?")
        echo "## Clients: ${client_count}" >> "$summary_file"
        echo "" >> "$summary_file"
    fi

    # Port Profiles
    if [ -f "${OUTPUT_DIR}/port_profiles.json" ]; then
        local pp_count
        pp_count=$(jq '(.data.data // .data // []) | length' "${OUTPUT_DIR}/port_profiles.json" 2>/dev/null || echo "0")
        [ "$pp_count" -gt 0 ] && echo "## Port Profiles: ${pp_count}" >> "$summary_file" && echo "" >> "$summary_file"
    fi

    # Export manifest
    echo "## Exported Files" >> "$summary_file"
    echo '```' >> "$summary_file"
    ls -1sh "${OUTPUT_DIR}/"*.json 2>/dev/null >> "$summary_file"
    echo '```' >> "$summary_file"

    log_info "Summary: ${summary_file}"
}

# ─── Main Commands ───────────────────────────────────────────────────────────

cmd_setup() {
    echo "UniFi API Toolkit — Setup"
    echo ""

    if [ -f "${SCRIPT_DIR}/.env" ]; then
        log_info "Found existing .env file"
        echo "  UDM_HOST=$(grep UDM_HOST "${SCRIPT_DIR}/.env" 2>/dev/null | cut -d= -f2)"
        echo "  UNIFI_SITE_ID=$(grep UNIFI_SITE_ID "${SCRIPT_DIR}/.env" 2>/dev/null | cut -d= -f2)"
        echo "  UNIFI_API_KEY=****"
        echo ""
        read -rp "Overwrite? (y/N): " overwrite
        if [ "$overwrite" != "y" ] && [ "$overwrite" != "Y" ]; then
            log_info "Keeping existing .env"
            return
        fi
    fi

    echo "Generate an API key in UniFi:"
    echo "  Network → Settings → Control Plane → Integrations"
    echo ""

    read -rp "UDM IP address (e.g., 192.168.10.1): " setup_host
    read -rp "API Key: " setup_key

    log_info "Fetching site ID..."
    local sites_response
    sites_response=$(curl -sk \
        -H "X-API-KEY: ${setup_key}" \
        "https://${setup_host}/proxy/network/integration/v1/sites" 2>/dev/null)

    local site_count
    site_count=$(echo "$sites_response" | jq '.totalCount // 0' 2>/dev/null)

    local setup_site=""

    if [ "$site_count" -eq 1 ] 2>/dev/null; then
        setup_site=$(echo "$sites_response" | jq -r '.data[0].id' 2>/dev/null)
        local site_name
        site_name=$(echo "$sites_response" | jq -r '.data[0].name' 2>/dev/null)
        log_info "Found site: ${site_name} (${setup_site})"
    elif [ "$site_count" -gt 1 ] 2>/dev/null; then
        echo ""
        echo "Multiple sites found:"
        echo "$sites_response" | jq -r '.data[] | "  \(.id) — \(.name)"' 2>/dev/null
        echo ""
        read -rp "Enter Site ID to use: " setup_site
    else
        log_warn "Could not auto-detect site ID"
        read -rp "Enter Site ID manually: " setup_site
    fi

    cat > "${SCRIPT_DIR}/.env" << EOF
# UniFi API Toolkit Configuration
# Generated: $(date)
# API: Integration v1 (X-API-KEY auth)
UDM_HOST=${setup_host}
UNIFI_API_KEY=${setup_key}
UNIFI_SITE_ID=${setup_site}
# OUTPUT_DIR=./unifi-exports
# DOCS_DIR=./Documents
EOF

    chmod 600 "${SCRIPT_DIR}/.env"
    log_info "Saved .env (permissions set to 600)"

    UDM_HOST="$setup_host"
    UNIFI_API_KEY="$setup_key"
    UNIFI_SITE_ID="$setup_site"
    api_test

    echo ""
    log_info "Setup complete. Run: $0 quick"
}

cmd_test() {
    validate_config
    api_test
}

cmd_discover() {
    validate_config
    set_base_url
    api_test
    discover_endpoints
}

cmd_export_all() {
    log_info "Full export starting..."
    validate_config
    mkdir -p "$OUTPUT_DIR"
    set_base_url
    api_test

    # Core exports (always available)
    export_devices
    export_clients
    export_networks
    export_firewall_policies

    # Firewall detail exports
    export_firewall_rules
    export_firewall_groups
    export_firewall_zones

    # Network config exports
    export_wlans
    export_port_profiles
    export_routes
    export_port_forwarding

    # Traffic management
    export_traffic_rules
    export_traffic_routes

    # VPN
    export_vpn

    generate_summary
    sanitize_exports

    log_section "Export Complete"
    log_info "Files saved to: ${OUTPUT_DIR}/"
    log_info "Total files: $(find "${OUTPUT_DIR}" -maxdepth 1 -name "*.json" -type f | wc -l) JSON exports"
    log_info "Total size: $(du -sh "${OUTPUT_DIR}" | cut -f1)"
    echo ""
    echo "  Next steps:"
    echo "    $(basename "$0") docs all        Generate markdown documentation"
    echo "    $(basename "$0") sanitize        Redact sensitive data before sharing"
    echo ""
}

cmd_export_quick() {
    log_info "Quick export (core config data)..."
    validate_config
    mkdir -p "$OUTPUT_DIR"
    set_base_url
    api_test

    export_networks
    export_firewall_policies
    export_devices
    export_firewall_groups
    export_firewall_zones
    export_wlans

    sanitize_exports

    log_section "Quick Export Complete"
    log_info "Files saved to: ${OUTPUT_DIR}/"
    echo ""
    echo "  For full export including clients, port profiles, routes:"
    echo "    $(basename "$0") all"
    echo ""
    echo "  Generate docs:"
    echo "    $(basename "$0") docs all"
}

cmd_single() {
    local target="${1:-}"
    if [ -z "$target" ]; then
        echo "Usage: $0 single <category>"
        echo ""
        echo "Categories:"
        echo "  devices          UniFi adopted devices"
        echo "  clients          Connected clients"
        echo "  networks         Network / VLAN configuration"
        echo "  policies         Firewall policies"
        echo "  rules            Firewall rules"
        echo "  groups           Firewall IP/port groups"
        echo "  zones            Firewall zone definitions"
        echo "  wlans            Wireless networks (SSIDs)"
        echo "  port-profiles    Switch port profiles"
        echo "  routes           Static routes"
        echo "  port-forwards    Port forwarding rules"
        echo "  traffic-rules    Traffic management rules"
        echo "  traffic-routes   Traffic route config"
        echo "  vpn              VPN configuration"
        exit 1
    fi

    validate_config
    mkdir -p "$OUTPUT_DIR"
    set_base_url
    api_test

    case "$target" in
        devices)         export_devices ;;
        clients)         export_clients ;;
        networks)        export_networks ;;
        policies)        export_firewall_policies ;;
        rules)           export_firewall_rules ;;
        groups)          export_firewall_groups ;;
        zones)           export_firewall_zones ;;
        wlans)           export_wlans ;;
        port-profiles)   export_port_profiles ;;
        routes)          export_routes ;;
        port-forwards)   export_port_forwarding ;;
        traffic-rules)   export_traffic_rules ;;
        traffic-routes)  export_traffic_routes ;;
        vpn)             export_vpn ;;
        *)               log_error "Unknown category: ${target}. Use 'single' without args to see options." && exit 1 ;;
    esac
}

cmd_raw() {
    local endpoint="${1:-}"
    if [ -z "$endpoint" ]; then
        echo "Usage: $0 raw <endpoint-path>"
        echo ""
        echo "Path is relative to /integration/v1/sites/{siteId}/"
        echo ""
        echo "Examples:"
        echo "  $0 raw devices"
        echo "  $0 raw clients"
        echo "  $0 raw firewall/policies"
        echo "  $0 raw firewall/groups"
        echo "  $0 raw wlans"
        echo "  $0 raw port-profiles"
        exit 1
    fi

    validate_config
    set_base_url
    api_get "$endpoint" | jq .
}

# ─── Usage ───────────────────────────────────────────────────────────────────

usage() {
    cat << EOF
UniFi Dream Machine API Toolkit (Integration API v1)

Usage: $(basename "$0") <command> [options]

${BOLD}Export Commands:${NC}
  setup              Interactive setup — saves config to .env
  test               Test API connectivity
  discover           Probe all known endpoints to see what's available
  all                Full export of all available data
  quick              Quick export (networks, firewall, devices, wlans)
  single <category>  Export single category
                     Categories: devices, clients, networks, policies, rules,
                     groups, zones, wlans, port-profiles, routes,
                     port-forwards, traffic-rules, traffic-routes, vpn
  raw <path>         Raw API query for any endpoint path

${BOLD}Documentation Commands:${NC}
  docs all           Generate all markdown documentation from exports
  docs hardware      UniFi device inventory and connection topology
  docs networks      VLAN structure, zones, and network config
  docs firewall      Firewall rules, groups, zones (full analysis)
  docs wifi          Wireless network (SSID) configuration
  docs clients       Client inventory grouped by VLAN
  docs port-profiles Switch port profile definitions

${BOLD}Analysis Commands:${NC}
  firewall summary   Quick overview of all firewall rules
  firewall export    Export all firewall-related data
  firewall groups    List firewall groups with members
  firewall zones     List firewall zones with network mappings

${BOLD}Sanitization:${NC}
  sanitize [dir]     Interactively redact sensitive data from exports

${BOLD}Workflow:${NC}
  1. First time:     $(basename "$0") setup
  2. Export data:    $(basename "$0") all
  3. Generate docs:  $(basename "$0") docs all
  4. Review & enrich generated markdown (add DHCP ranges, static IPs, etc.)
  5. Commit to GitHub

${BOLD}Options:${NC}
  --docs-dir <path>    Override documentation output directory (default: ./Documents)
  --export-dir <path>  Override JSON export directory (default: ./unifi-exports)

${BOLD}Examples:${NC}
  $(basename "$0") setup
  $(basename "$0") all && $(basename "$0") docs all
  $(basename "$0") firewall summary
  $(basename "$0") docs firewall --docs-dir ~/network-docs/Documents
  $(basename "$0") single clients && $(basename "$0") docs clients
  $(basename "$0") sanitize ./unifi-exports
  $(basename "$0") raw firewall/groups | jq '.data[] | .name'

EOF
}

# ─── Entry Point ─────────────────────────────────────────────────────────────

check_dependencies

case "${1:-}" in
    setup)      cmd_setup ;;
    test)       cmd_test ;;
    discover)   cmd_discover ;;
    all)        cmd_export_all ;;
    quick)      cmd_export_quick ;;
    single)     cmd_single "${2:-}" ;;
    sanitize)   cmd_sanitize "$@" ;;
    raw)        cmd_raw "${2:-}" ;;
    docs)       shift; cmd_docs "$@" ;;
    firewall)   shift; cmd_firewall "$@" ;;
    -h|--help)  usage ;;
    *)          usage ;;
esac
