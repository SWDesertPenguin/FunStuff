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
DATE_STAMP=$(date +%Y%m%d-%H%M%S)

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
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

    # First request to get totalCount
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

    # Check if we need to paginate
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
            # Merge arrays
            current_data=$(jq -sc '.[0] + .[1]' <(echo "$current_data") <(echo "$page_data"))
            offset=$((offset + limit))
        done
    fi

    # Return consistent format
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

    # Print summary
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

    # Print summary
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

# ─── Sanitization ────────────────────────────────────────────────────────────

sanitize_exports() {
    log_section "Sanitization Report"

    log_warn "Review before sharing:"
    echo ""
    echo "  MAY contain sensitive data:"
    echo "  ├── clients.json             → MACs, hostnames, IPs, device names"
    echo "  └── wlans.json               → SSIDs, possibly passwords"
    echo ""
    echo "  Generally safe to share as-is:"
    echo "  ├── devices.json             → UniFi device inventory"
    echo "  ├── networks.json            → VLAN/subnet structure"
    echo "  ├── firewall_policies.json   → Firewall policy config"
    echo "  └── firewall_rules.json      → Firewall rules"
    echo ""
    log_info "Internal IPs (RFC1918) are fine to share."
    log_info "Run '$(basename "$0") sanitize' to interactively redact sensitive data."
}

# ─── Sanitization Engine ─────────────────────────────────────────────────────

# Detect what sensitive data exists in a JSON file
detect_sensitive_data() {
    local filepath="$1"
    local filename
    filename=$(basename "$filepath")
    local findings=()

    local all_strings
    all_strings=$(jq -r '.. | strings' "$filepath" 2>/dev/null)

    # Check for public (non-RFC1918, non-special) IPs
    local pub_ips
    pub_ips=$(echo "$all_strings" | \
        grep -oP '\b(?!10\.)(?!172\.(1[6-9]|2[0-9]|3[01])\.)(?!192\.168\.)(?!127\.)(?!0\.0\.0\.0)(?!169\.254\.)(?!22[4-9]\.)(?!23[0-9]\.)(?!24[0-9]\.)(?!25[0-5]\.)(([0-9]{1,3}\.){3}[0-9]{1,3})\b' 2>/dev/null | \
        sort -u)
    local pub_ip_count
    pub_ip_count=$(echo "$pub_ips" | grep -c . 2>/dev/null || echo "0")
    [ "$pub_ip_count" -gt 0 ] && findings+=("wan_ip|Public/WAN IPs|Replace with 203.0.113.x (documentation range)|${pub_ip_count} unique")

    # Check for MAC addresses
    local mac_count
    mac_count=$(echo "$all_strings" | \
        grep -oiP '([0-9a-f]{2}:){5}[0-9a-f]{2}' 2>/dev/null | sort -u | grep -c . 2>/dev/null || echo "0")
    [ "$mac_count" -gt 0 ] && findings+=("mac|MAC Addresses|Replace with AA:BB:CC:xx:xx:xx|${mac_count} unique")

    # File-specific checks
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
        firewall_policies.json|firewall_rules.json)
            # Public IPs already caught above — no extra checks needed
            ;;
        networks.json)
            # Networks contain subnet info which is fine (RFC1918) but check for WAN
            ;;
    esac

    # Return findings
    printf '%s\n' "${findings[@]}"
}

# Apply sanitization to a file using jq and sed
apply_sanitization() {
    local filepath="$1"
    local output_path="$2"
    shift 2
    local categories=("$@")

    # Work on a temp file to avoid issues
    local tmpfile
    tmpfile=$(mktemp)
    cp "$filepath" "$tmpfile"

    for category in "${categories[@]}"; do
        case "$category" in
            wan_ip)
                # Replace public IPs with documentation range IPs (RFC5737: 203.0.113.0/24)
                local pub_ips
                pub_ips=$(jq -r '.. | strings' "$tmpfile" 2>/dev/null | \
                    grep -oP '\b(?!10\.)(?!172\.(1[6-9]|2[0-9]|3[01])\.)(?!192\.168\.)(?!127\.)(?!0\.0\.0\.0)(?!169\.254\.)(?!22[4-9]\.)(?!23[0-9]\.)(?!24[0-9]\.)(?!25[0-5]\.)(([0-9]{1,3}\.){3}[0-9]{1,3})\b' 2>/dev/null | \
                    sort -u)

                local counter=0
                while IFS= read -r ip; do
                    [ -z "$ip" ] && continue
                    counter=$((counter + 1))
                    local replacement="203.0.113.${counter}"
                    # Escape dots for sed
                    local escaped_ip="${ip//./\\.}"
                    sed -i "s/${escaped_ip}/${replacement}/g" "$tmpfile"
                done <<< "$pub_ips"
                ;;
            mac)
                # Replace MAC addresses consistently — same MAC always gets same replacement
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
                    # Replace both lowercase and uppercase variants
                    local mac_upper="${mac^^}"
                    sed -i "s/${mac}/${replacement}/g; s/${mac_upper}/${replacement}/g" "$tmpfile"
                done <<< "$macs"
                ;;
            serial)
                # Replace serial numbers in device data
                jq '
                    (.data.data // .data // []) |= [to_entries[] | .value |=
                        (if .serial then .serial = "REDACTED-\((.serial | length) as $l | .serial[($l-4):])}"
                        else . end)
                    | .value]
                ' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
            devname)
                # Replace device names with sequential generic names
                jq '
                    (.data.data // .data // []) |= [to_entries[] |
                        .value.name = "device-\(.key + 1)"
                    | .value]
                ' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
            hostname)
                # Replace hostnames and names in client data
                jq '
                    (.data.data // .data // []) |= [to_entries[] | .value |=
                        (if .hostname then .hostname = "host-\(.key + 1)" else . end |
                         if .name then .name = "host-\(.key + 1)" else . end)
                    | .value]
                ' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
            clientname)
                # Replace display names in client data
                jq '
                    (.data.data // .data // []) |= [to_entries[] | .value |=
                        (if .displayName then .displayName = "client-\(.key + 1)" else . end |
                         if .display_name then .display_name = "client-\(.key + 1)" else . end)
                    | .value]
                ' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
            ssid)
                jq '
                    (.data.data // .data // []) |= [to_entries[] | .value |=
                        (if .name then .name = "WiFi-\(.key + 1)" else . end |
                         if .ssid then .ssid = "WiFi-\(.key + 1)" else . end)
                    | .value]
                ' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
            password)
                jq '
                    (.data.data // .data // []) |= map(
                        if .x_passphrase then .x_passphrase = "REDACTED" else . end |
                        if .password then .password = "REDACTED" else . end
                    )
                ' "$tmpfile" > "${tmpfile}.new" 2>/dev/null && mv "${tmpfile}.new" "$tmpfile" || true
                ;;
        esac
    done

    # Update metadata to note sanitization
    local cat_list
    cat_list=$(IFS=', '; echo "${categories[*]}")
    jq --arg cats "$cat_list" --arg date "$(date -Iseconds)" \
        'if ._metadata then ._metadata.sanitized = $cats | ._metadata.sanitized_date = $date else . end' \
        "$tmpfile" > "${tmpfile}.final" 2>/dev/null && mv "${tmpfile}.final" "$output_path" || mv "$tmpfile" "$output_path"

    rm -f "$tmpfile" "${tmpfile}.new" "${tmpfile}.final" 2>/dev/null
}

# Interactive sanitization command
cmd_sanitize() {
    local source_dir="${2:-${OUTPUT_DIR}}"

    if [ ! -d "$source_dir" ]; then
        log_error "Export directory not found: ${source_dir}"
        echo "Run an export first: $(basename "$0") quick"
        exit 1
    fi

    # Find all JSON files
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

    # List files with record counts
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

    # Parse selection
    local selected_indices=()
    if [ "$file_selection" = "all" ]; then
        for i in "${!json_files[@]}"; do
            selected_indices+=("$i")
        done
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

    # Create output directory
    local sanitized_dir="${source_dir}/sanitized"
    mkdir -p "$sanitized_dir"

    # Process each selected file
    local files_processed=0
    local summary_lines=()

    for idx in "${selected_indices[@]}"; do
        local filepath="${json_files[$idx]}"
        local filename="${file_names[$idx]}"

        log_section "Sanitizing: ${filename}"

        # Detect sensitive data
        local findings
        findings=$(detect_sensitive_data "$filepath")

        if [ -z "$findings" ]; then
            log_info "No sensitive data detected — skipping"
            # Copy as-is
            cp "$filepath" "${sanitized_dir}/${filename}"
            summary_lines+=("  ├── ${filename}  → copied as-is (nothing to sanitize)")
            continue
        fi

        # Display options
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

        # Add "all" option
        printf "    ${CYAN}%d${NC}) %-25s → %s\n" "$option_num" "All of the above" "Apply all sanitizations"

        echo ""
        read -rp "  Select options (comma-separated numbers, or ${option_num} for all): " option_selection

        # Parse option selection
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

        # Apply sanitization
        log_info "Applying: ${selected_categories[*]}"
        apply_sanitization "$filepath" "${sanitized_dir}/${filename}" "${selected_categories[@]}"

        local redacted_list
        redacted_list=$(IFS=', '; echo "${selected_categories[*]}")
        summary_lines+=("  ├── ${filename}  → ${redacted_list} redacted")
        files_processed=$((files_processed + 1))

        log_info "Saved: ${sanitized_dir}/${filename}"
    done

    # Copy non-selected JSON files as-is
    for i in "${!json_files[@]}"; do
        local filename="${file_names[$i]}"
        if [ ! -f "${sanitized_dir}/${filename}" ]; then
            cp "${json_files[$i]}" "${sanitized_dir}/${filename}"
        fi
    done

    # Print summary
    log_section "Sanitization Complete"
    echo ""
    echo "  Output: ${sanitized_dir}/"
    echo ""
    for line in "${summary_lines[@]}"; do
        echo -e "$line"
    done

    # Fix last line to use └
    echo ""
    log_info "Sanitized files are safe to share. Originals untouched."
    log_info "Upload files from ${sanitized_dir}/ to Claude."

    # Generate mapping file by diffing original vs sanitized
    if [ "$files_processed" -gt 0 ]; then
        local map_file="${sanitized_dir}/SANITIZE_MAP.txt"
        echo "# Sanitization Mapping — DO NOT SHARE THIS FILE" > "$map_file"
        echo "# Generated: $(date)" >> "$map_file"
        echo "# Compare original and sanitized files to see what changed" >> "$map_file"
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

    if [ -f "${OUTPUT_DIR}/networks.json" ]; then
        echo "## Networks" >> "$summary_file"
        echo '```' >> "$summary_file"
        jq -r '.data.data[] | "\(.name // "unnamed") | VLAN: \(.vlan // "untagged") | Subnet: \(.subnet // "n/a")"' \
            "${OUTPUT_DIR}/networks.json" >> "$summary_file" 2>/dev/null || echo "(parse error)" >> "$summary_file"
        echo '```' >> "$summary_file"
        echo "" >> "$summary_file"
    fi

    if [ -f "${OUTPUT_DIR}/devices.json" ]; then
        echo "## Devices" >> "$summary_file"
        echo '```' >> "$summary_file"
        jq -r '.data.data[] | "\(.name // "unnamed") | \(.model // "?") | IP: \(.ip // "?")"' \
            "${OUTPUT_DIR}/devices.json" >> "$summary_file" 2>/dev/null || echo "(parse error)" >> "$summary_file"
        echo '```' >> "$summary_file"
        echo "" >> "$summary_file"
    fi

    if [ -f "${OUTPUT_DIR}/firewall_policies.json" ]; then
        local fw_count
        fw_count=$(jq '.data.data | length' "${OUTPUT_DIR}/firewall_policies.json" 2>/dev/null || echo "?")
        echo "## Firewall Policies: ${fw_count}" >> "$summary_file"
        echo "" >> "$summary_file"
    fi

    if [ -f "${OUTPUT_DIR}/clients.json" ]; then
        local client_count
        client_count=$(jq '.data.data | length' "${OUTPUT_DIR}/clients.json" 2>/dev/null || echo "?")
        echo "## Clients: ${client_count}" >> "$summary_file"
        echo "" >> "$summary_file"
    fi

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

    # Fetch site ID automatically
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
EOF

    chmod 600 "${SCRIPT_DIR}/.env"
    log_info "Saved .env (permissions set to 600)"

    # Test connection
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

    export_devices
    export_clients
    export_networks
    export_firewall_policies
    export_firewall_rules

    # Try additional endpoints silently
    log_section "Additional Endpoints"

    for ep in "wlans" "port-forwarding" "routes" "firewall/groups" "firewall/zones"; do
        local safe_name
        safe_name=$(echo "$ep" | tr '/' '_')
        local data
        data=$(api_get "$ep" "$ep" 2>/dev/null)
        local count
        count=$(echo "$data" | jq '.data | length' 2>/dev/null || echo "0")
        if [ "$count" -gt 0 ] 2>/dev/null; then
            save_output "$data" "${safe_name}.json" "${ep}"
        else
            log_info "Skipped ${ep} (empty or unavailable)"
        fi
    done

    generate_summary
    sanitize_exports

    log_section "Export Complete"
    log_info "Files saved to: ${OUTPUT_DIR}/"
    log_info "Total files: $(ls -1 "${OUTPUT_DIR}" | wc -l)"
    log_info "Total size: $(du -sh "${OUTPUT_DIR}" | cut -f1)"
    echo ""
    log_info "Share with Claude: networks.json, firewall_policies.json, devices.json"
}

cmd_export_quick() {
    log_info "Quick export (networks, firewall, devices)..."
    validate_config
    mkdir -p "$OUTPUT_DIR"
    set_base_url
    api_test

    export_networks
    export_firewall_policies
    export_devices

    sanitize_exports

    log_section "Quick Export Complete"
    log_info "Files saved to: ${OUTPUT_DIR}/"
}

cmd_single() {
    local target="${1:-}"
    if [ -z "$target" ]; then
        echo "Usage: $0 single <category>"
        echo ""
        echo "Categories: devices, clients, networks, policies, rules"
        echo ""
        echo "Or use 'raw' for any endpoint path"
        exit 1
    fi

    validate_config
    mkdir -p "$OUTPUT_DIR"
    set_base_url
    api_test

    case "$target" in
        devices)    export_devices ;;
        clients)    export_clients ;;
        networks)   export_networks ;;
        policies)   export_firewall_policies ;;
        rules)      export_firewall_rules ;;
        *)          log_error "Unknown category: ${target}. Use 'raw' for custom endpoints." && exit 1 ;;
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
        echo "  $0 raw networks"
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

Commands:
  setup         Interactive setup — saves config to .env
  test          Test API connectivity
  discover      Probe all known endpoints to see what's available
  all           Full export of all available data
  quick         Quick export (networks, firewall policies, devices)
  single <x>    Export single category
                Options: devices, clients, networks, policies, rules
  sanitize      Interactively redact sensitive data from exported files
  raw <path>    Raw API query for any endpoint path

First-Time Setup:
  1. Generate API key: Network → Settings → Control Plane → Integrations
  2. Run: $(basename "$0") setup
  3. Run: $(basename "$0") quick

Examples:
  $(basename "$0") setup
  $(basename "$0") discover
  $(basename "$0") quick
  $(basename "$0") all
  $(basename "$0") single clients
  $(basename "$0") sanitize                  # Sanitize files in default export dir
  $(basename "$0") sanitize ./my-exports     # Sanitize files in specific dir
  $(basename "$0") raw firewall/policies

Sharing with Claude:
  1. Run 'quick' or 'all'
  2. Run 'sanitize' to interactively redact sensitive data
  3. Upload JSON files from sanitized/ subdirectory
  4. Start with: networks.json, firewall_policies.json, devices.json

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
    -h|--help)  usage ;;
    *)          usage ;;
esac
