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

# Load config with validation (tries deploy dir first, then exitmap root)
load_config() {
    local config_file="${1:-}"
    
    if [[ -n "$config_file" && -f "$config_file" ]]; then
        validate_config "$config_file"
        source "$config_file"
        return 0
    fi
    
    if [[ -f "$DEPLOY_DIR/config.env" ]]; then
        validate_config "$DEPLOY_DIR/config.env"
        source "$DEPLOY_DIR/config.env"
        return 0
    fi
    
    if [[ -f "$EXITMAP_DIR/config.env" ]]; then
        validate_config "$EXITMAP_DIR/config.env"
        source "$EXITMAP_DIR/config.env"
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

# Create directory if it doesn't exist
ensure_dir() {
    local dir="$1"
    [[ -d "$dir" ]] || mkdir -p "$dir"
}

# Get timestamp for filenames
get_timestamp() {
    date '+%Y-%m-%d_%H%M%S'
}

# Get today's date for markers
get_today() {
    date '+%Y-%m-%d'
}
