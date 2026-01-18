#!/usr/bin/env bash
# exitmap DNS Health - Common Upload Functions
# Shared by upload-do.sh and upload-r2.sh
# Uses unique remote names (exitmap-r2, exitmap-spaces) to avoid config conflicts.

set -euo pipefail

# Source shared functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Remote names (unique to this project)
EXITMAP_R2_REMOTE="exitmap-r2"
EXITMAP_DO_REMOTE="exitmap-spaces"

# Cached rclone options (populated by init_upload)
declare -a RCLONE_OPTS_ARRAY=()

# Initialize paths and config
init_upload() {
    init_paths 2  # Use grandparent caller's location
    load_config || true
    
    SOURCE_DIR="${1:-${OUTPUT_DIR:-$DEPLOY_DIR/public}}"
    BACKUP_DIR="${BACKUP_DIR:-$DEPLOY_DIR/backups}"
    LOG_DIR="${LOG_DIR:-$DEPLOY_DIR/logs}"
    RCLONE="${RCLONE_PATH:-$(command -v rclone 2>/dev/null || echo "$HOME/bin/rclone")}"
    TODAY=$(get_today)
    TIMESTAMP=$(get_timestamp)
    
    ensure_dir "$LOG_DIR"
    ensure_dir "$BACKUP_DIR"
    
    # Rclone defaults (can override per-backend)
    : "${TRANSFERS:=64}" "${CHECKERS:=128}" "${BUFFER:=64M}" "${S3_CONC:=16}" "${S3_CHUNK:=16M}"
    
    # Cache rclone options array once
    RCLONE_OPTS_ARRAY=(
        "--transfers=$TRANSFERS" "--checkers=$CHECKERS" "--buffer-size=$BUFFER"
        "--s3-upload-concurrency=$S3_CONC" "--s3-chunk-size=$S3_CHUNK"
        "--fast-list" "--stats=10s" "--stats-one-line" "--log-level=NOTICE"
        "--retries=5" "--retries-sleep=2s" "--low-level-retries=10"
    )
}

check_rclone() {
    [[ -x "$RCLONE" ]] || { log_error "rclone not found at $RCLONE"; return 1; }
}

# Remote setup (creates if not exists)
ensure_remote() {
    local name=$1 provider=$2; shift 2
    "$RCLONE" listremotes 2>/dev/null | grep -q "^${name}:$" && return 0
    log "Creating remote '$name'..."
    "$RCLONE" config create "$name" s3 provider="$provider" "$@" --non-interactive >/dev/null
    log_success "Remote '$name' configured"
}

ensure_r2_remote() {
    [[ -n "${R2_ACCESS_KEY_ID:-}" && -n "${R2_SECRET_ACCESS_KEY:-}" && -n "${CLOUDFLARE_ACCOUNT_ID:-}" ]] || {
        log_error "R2 credentials not set (R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, CLOUDFLARE_ACCOUNT_ID)"; return 1
    }
    ensure_remote "$EXITMAP_R2_REMOTE" Cloudflare \
        access_key_id="$R2_ACCESS_KEY_ID" \
        secret_access_key="$R2_SECRET_ACCESS_KEY" \
        endpoint="https://${CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com" \
        acl=private
}

ensure_do_remote() {
    [[ -n "${DO_SPACES_KEY:-}" && -n "${DO_SPACES_SECRET:-}" ]] || {
        log_error "DO credentials not set (DO_SPACES_KEY, DO_SPACES_SECRET)"; return 1
    }
    ensure_remote "$EXITMAP_DO_REMOTE" DigitalOcean \
        access_key_id="$DO_SPACES_KEY" \
        secret_access_key="$DO_SPACES_SECRET" \
        endpoint="${DO_SPACES_REGION:-nyc3}.digitaloceanspaces.com" \
        acl=public-read no_check_bucket=true
}

# Backup if not done today (returns 0 if backup made, 1 if skipped)
maybe_backup() {
    local bucket="$1" marker="$2" type="$3" force="${4:-false}"
    [[ "$force" == "true" ]] || { [[ -f "$marker" && "$(cat "$marker")" == "$TODAY" ]] && return 1; }
    
    local target
    if [[ "$type" == "local" ]]; then
        target="$BACKUP_DIR/backup-$TIMESTAMP"
        log "Local backup → $target"
        mkdir -p "$target"
        "$RCLONE" sync "$bucket" "$target" --exclude "_backups/**" "${RCLONE_OPTS_ARRAY[@]}" 2>&1 | head -5
    else
        target="$bucket/_backups/$TIMESTAMP"
        log "Remote backup → $target"
        "$RCLONE" sync "$bucket" "$target" --exclude "_backups/**" "${RCLONE_OPTS_ARRAY[@]}" 2>&1 | head -5
    fi
    echo "$TODAY" > "$marker"
    log_success "${type^} backup done"
}

# Main upload function (syncs JSON files, excludes index.html)
do_upload() {
    local bucket="$1"
    log "Syncing $SOURCE_DIR → $bucket"
    "$RCLONE" sync "$SOURCE_DIR" "$bucket" \
        --exclude "_backups/**" \
        --exclude "index.html" \
        --include "*.json" \
        --include "archives/*.tar.gz" \
        "${RCLONE_OPTS_ARRAY[@]}" 2>&1 | head -10
    log_success "Upload complete"
}

# Upload specific files (for incremental updates)
upload_files() {
    local bucket="$1"; shift
    for file in "$@"; do
        [[ -f "$file" ]] || { log_warn "File not found: $file"; continue; }
        local basename=$(basename "$file")
        log "Uploading $basename..."
        "$RCLONE" copyto "$file" "$bucket/$basename" "${RCLONE_OPTS_ARRAY[@]}" 2>&1 | head -3
    done
    log_success "Files uploaded"
}

# List backups helper
list_backups() {
    local bucket="$1"
    local storage="$2"
    local storage_lower=$(echo "$storage" | tr '[:upper:]' '[:lower:]')
    local local_marker="$LOG_DIR/last-${storage_lower}-local-backup-date"
    local remote_marker="$LOG_DIR/last-${storage_lower}-backup-date"
    
    echo "📦 Local: $(ls -1dt "$BACKUP_DIR"/backup-* 2>/dev/null | head -3 | tr '\n' ' ' || echo none)"
    echo "📦 ${storage}: $("$RCLONE" lsf "$bucket/_backups/" --dirs-only 2>/dev/null | sort -r | head -3 | tr '\n' ' ' || echo none)"
    echo "📅 Last local: $(cat "$local_marker" 2>/dev/null || echo never)"
    echo "📅 Last ${storage}: $(cat "$remote_marker" 2>/dev/null || echo never)"
}
