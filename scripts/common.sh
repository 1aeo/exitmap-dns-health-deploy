#!/usr/bin/env bash
# exitmap DNS Health - Shared Functions
# Source this file in other scripts: source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
#
# Adapted from aroivalidator-deploy for exitmap.

# Prevent multiple sourcing
[[ -n "${_EXITMAP_COMMON_LOADED:-}" ]] && return 0
_EXITMAP_COMMON_LOADED=1

set -euo pipefail

# === Path Detection (call init_paths from sourcing script) ===
init_paths() {
    # Use BASH_SOURCE to get the calling script's directory
    # Default to index 1 (direct caller), but allow override for nested sourcing
    local caller_idx=${1:-1}
    local max_idx=$((${#BASH_SOURCE[@]} - 1))
    # Clamp to valid range
    [[ $caller_idx -gt $max_idx ]] && caller_idx=$max_idx
    [[ $caller_idx -lt 0 ]] && caller_idx=0
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[$caller_idx]}")" && pwd)"
    DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
    EXITMAP_DIR="$(dirname "$DEPLOY_DIR")"
    export SCRIPT_DIR DEPLOY_DIR EXITMAP_DIR
}

# === Config Validation & Loading ===
# Returns 0 if config is valid, 1 otherwise. Warns on insecure permissions.
validate_config() {
    local config_file="${1:-$DEPLOY_DIR/config.env}"
    [[ -f "$config_file" ]] || return 1
    
    local perms
    perms=$(stat -c '%a' "$config_file" 2>/dev/null || echo "644")
    # Check world-readable/writable (last digit should be 0 or 4)
    if [[ "${perms: -1}" != "0" && "${perms: -1}" != "4" ]]; then
        echo "Warning: $config_file has insecure permissions ($perms). Run: chmod 600 $config_file" >&2
    fi
    return 0
}

# Validate config values are safe (no shell injection, valid types)
# Call after sourcing config to ensure values are sanitized
validate_config_values() {
    local errors=0
    
    # Pattern for safe path characters (alphanumeric, underscore, dash, dot, slash, $, ~)
    local path_pattern='^[a-zA-Z0-9_./$~-]+$'
    
    # Validate path variables don't contain shell metacharacters
    for var in DEPLOY_PATH OUTPUT_DIR LOG_DIR BACKUP_DIR TMP_DIR EXITMAP_DIR RCLONE_PATH; do
        local value="${!var:-}"
        if [[ -n "$value" ]] && ! [[ "$value" =~ $path_pattern ]]; then
            echo "Error: $var contains invalid characters: $value" >&2
            ((errors++))
        fi
    done
    
    # Validate numeric values
    for var in CACHE_TTL_LATEST CACHE_TTL_HISTORICAL BUILD_DELAY DELAY_NOISE \
               DNS_QUERY_TIMEOUT DNS_MAX_RETRIES DNS_HARD_TIMEOUT \
               TOR_BOOTSTRAP_TIMEOUT TOR_MAX_BOOTSTRAP_RETRIES TOR_PROGRESS_CHECK_INTERVAL \
               WAVE_BATCH_SIZE WAVE_MAX_RETRIES MAX_PENDING_CIRCUITS \
               RCLONE_TRANSFERS RCLONE_CHECKERS DO_RCLONE_TRANSFERS DO_RCLONE_CHECKERS \
               ANALYSIS_KEEP_COUNT EXITMAP_GRACE_TIMEOUT; do
        local value="${!var:-}"
        if [[ -n "$value" ]] && ! [[ "$value" =~ ^[0-9]+$ ]]; then
            echo "Error: $var must be numeric, got: $value" >&2
            ((errors++))
        fi
    done
    
    # Validate boolean values
    for var in DO_ENABLED R2_ENABLED CLOUD_UPLOAD ALL_EXITS RELIABLE_FIRST_HOP \
               CLEANUP_OLD DO_SPACES_CDN; do
        local value="${!var:-}"
        if [[ -n "$value" ]] && ! [[ "$value" =~ ^(true|false)$ ]]; then
            echo "Error: $var must be true/false, got: $value" >&2
            ((errors++))
        fi
    done
    
    # Validate DNS_RETRY_DELAY is a valid float
    if [[ -n "${DNS_RETRY_DELAY:-}" ]] && ! [[ "$DNS_RETRY_DELAY" =~ ^[0-9]+\.?[0-9]*$ ]]; then
        echo "Error: DNS_RETRY_DELAY must be numeric, got: $DNS_RETRY_DELAY" >&2
        ((errors++))
    fi
    
    [[ $errors -eq 0 ]] || return 1
}

# Load config with validation (tries deploy dir first, then exitmap root)
load_config() {
    local config_file="${1:-}"
    local loaded=false
    
    if [[ -n "$config_file" && -f "$config_file" ]]; then
        validate_config "$config_file"
        source "$config_file"
        loaded=true
    elif [[ -f "$DEPLOY_DIR/config.env" ]]; then
        validate_config "$DEPLOY_DIR/config.env"
        source "$DEPLOY_DIR/config.env"
        loaded=true
    elif [[ -f "$EXITMAP_DIR/config.env" ]]; then
        validate_config "$EXITMAP_DIR/config.env"
        source "$EXITMAP_DIR/config.env"
        loaded=true
    fi
    
    if $loaded; then
        # Validate sourced values are safe
        validate_config_values || {
            echo "Error: Config validation failed. Fix the above errors in config.env" >&2
            return 1
        }
        return 0
    fi
    
    return 1
}

# === Logging Functions ===
_log_ts() { date '+%H:%M:%S'; }

log()         { echo "[$(_log_ts)]${STORAGE_NAME:+ [$STORAGE_NAME]} $1"; }
log_error()   { echo "[$(_log_ts)] ❌ $1" >&2; }
log_success() { echo "[$(_log_ts)] ✅ $1"; }
log_warn()    { echo "[$(_log_ts)] ⚠️  $1" >&2; }

# === Utility Functions ===
# Check if command exists
require_cmd() {
    command -v "$1" &>/dev/null || { log_error "$1 required but not found"; return 1; }
}

# Validate string matches pattern (for security checks)
validate_pattern() {
    local value="$1" pattern="$2" name="${3:-value}"
    [[ "$value" =~ $pattern ]] || { log_error "Invalid $name: $value"; return 1; }
}

# Create directory if it doesn't exist, with optional mode
# Usage: ensure_dir /path/to/dir [mode]
# Example: ensure_dir "$BACKUP_DIR" 700
ensure_dir() {
    local dir="$1"
    local mode="${2:-755}"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        chmod "$mode" "$dir"
    fi
}

# Get timestamp for filenames
get_timestamp() {
    date '+%Y-%m-%d_%H%M%S'
}

# Get today's date for markers
get_today() {
    date '+%Y-%m-%d'
}
