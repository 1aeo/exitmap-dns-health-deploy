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

# Coordination & staging defaults (can be overridden by --no-local-backup or env)
SKIP_LOCAL_BACKUP="${SKIP_LOCAL_BACKUP:-false}"
LOCAL_BACKUP_STAGING_DIR=""

cleanup_local_backup_staging() {
    if [[ -n "${LOCAL_BACKUP_STAGING_DIR:-}" && -d "$LOCAL_BACKUP_STAGING_DIR" ]]; then
        rm -rf -- "$LOCAL_BACKUP_STAGING_DIR" || true
        LOCAL_BACKUP_STAGING_DIR=""
    fi
}

write_marker_atomically() {
    local marker="$1"
    local value="$2"
    local tmp_marker="${marker}.tmp.$$"
    ensure_dir "$(dirname "$marker")"
    printf '%s\n' "$value" > "$tmp_marker"
    mv -f -- "$tmp_marker" "$marker"
}

run_rclone_logged() {
    local max_lines="$1"
    shift
    local log_file rc=0
    log_file=$(mktemp "${TMPDIR:-/tmp}/exitmap-rclone.XXXXXX")
    "$RCLONE" "$@" >"$log_file" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        if [[ "$max_lines" -gt 0 && -s "$log_file" ]]; then
            head -n "$max_lines" "$log_file"
        fi
    else
        if [[ -s "$log_file" ]]; then
            tail -n 20 "$log_file" >&2 || true
        fi
    fi
    rm -f -- "$log_file"
    return "$rc"
}

# Initialize paths and config
init_upload() {
    init_paths 2  # Use grandparent caller's location
    load_config || true
    
    SOURCE_DIR="${1:-${OUTPUT_DIR:-$DEPLOY_DIR/public}}"
    BACKUP_DIR="${BACKUP_DIR:-$DEPLOY_DIR/backups}"
    LOG_DIR="${LOG_DIR:-$DEPLOY_DIR/logs}"
    LOCAL_BACKUP_MARKER="${LOCAL_BACKUP_MARKER:-$LOG_DIR/last-local-backup-date}"
    LOCAL_BACKUP_LOCK_FILE="${LOCAL_BACKUP_LOCK_FILE:-$LOG_DIR/.local-backup.lock}"
    RCLONE="${RCLONE_PATH:-$(command -v rclone 2>/dev/null || echo "$HOME/bin/rclone")}"
    TODAY=$(get_today)
    TIMESTAMP=$(get_timestamp)
    
    ensure_dir "$LOG_DIR"
    ensure_dir "$BACKUP_DIR" 700  # Restrict backup access to owner only
    
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

# Backup if not done today (returns 0 if backup made, 1 if skipped/failed)
maybe_backup() {
    local bucket="$1" marker="$2" type="$3" force="${4:-false}"

    if [[ "$type" == "local" ]]; then
        if [[ "${SKIP_LOCAL_BACKUP:-false}" == "true" && "$force" != "true" ]]; then
            log "Local backup skipped (--no-local-backup)"
            return 1
        fi
        if [[ "$force" != "true" && -f "$marker" && "$(cat "$marker" 2>/dev/null || true)" == "$TODAY" ]]; then
            return 1
        fi

        ensure_dir "$(dirname "$LOCAL_BACKUP_LOCK_FILE")"
        exec 7>"$LOCAL_BACKUP_LOCK_FILE"
        if ! flock -n 7; then
            exec 7>&-
            log "Local backup skipped (another upload holds local backup lock)"
            return 1
        fi

        # Re-check shared marker after acquiring lock in case sibling upload just finished
        if [[ "$force" != "true" && -f "$marker" && "$(cat "$marker" 2>/dev/null || true)" == "$TODAY" ]]; then
            exec 7>&-
            return 1
        fi

        local ts final_target tmp_target
        ts=$(get_timestamp)
        final_target="$BACKUP_DIR/backup-${ts}"
        [[ -e "$final_target" ]] && final_target="${final_target}-$$"
        tmp_target="$BACKUP_DIR/backup-${ts}.tmp.$$"

        log "Local backup → $final_target"
        LOCAL_BACKUP_STAGING_DIR="$tmp_target"
        mkdir -p "$tmp_target"

        if ! run_rclone_logged 5 sync "$bucket" "$tmp_target" --exclude "_backups/**" "${RCLONE_OPTS_ARRAY[@]}"; then
            log_warn "Local backup failed; cleaning staging directory"
            rm -rf -- "$tmp_target" || true
            LOCAL_BACKUP_STAGING_DIR=""
            exec 7>&-
            return 1
        fi

        mv -- "$tmp_target" "$final_target"
        LOCAL_BACKUP_STAGING_DIR=""
        write_marker_atomically "$marker" "$TODAY"
        exec 7>&-
        log_success "Local backup done"
        return 0
    fi

    [[ "$force" == "true" ]] || { [[ -f "$marker" && "$(cat "$marker" 2>/dev/null || true)" == "$TODAY" ]] && return 1; }

    local target="$bucket/_backups/$TIMESTAMP"
    log "Remote backup → $target"
    if ! run_rclone_logged 5 sync "$bucket" "$target" --exclude "_backups/**" "${RCLONE_OPTS_ARRAY[@]}"; then
        log_warn "Remote backup failed; marker not updated"
        return 1
    fi
    write_marker_atomically "$marker" "$TODAY"
    log_success "Remote backup done"
}

# Main upload function (syncs JSON files, excludes index.html and _backups)
do_upload() {
    local bucket="$1"
    log "Syncing $SOURCE_DIR → $bucket"
    run_rclone_logged 10 sync "$SOURCE_DIR" "$bucket" \
        --filter "- _backups/**" \
        --filter "- index.html" \
        --filter "+ *.json" \
        --filter "+ archives/*.tar.gz" \
        --filter "- *" \
        "${RCLONE_OPTS_ARRAY[@]}"
    log_success "Upload complete"
}

# Upload specific files (for incremental updates)
upload_files() {
    local bucket="$1"; shift
    for file in "$@"; do
        [[ -f "$file" ]] || { log_warn "File not found: $file"; continue; }
        local file_basename
        file_basename=$(basename "$file")
        log "Uploading $file_basename..."
        run_rclone_logged 3 copyto "$file" "$bucket/$file_basename" "${RCLONE_OPTS_ARRAY[@]}"
    done
    log_success "Files uploaded"
}

# List backups helper
list_backups() {
    local bucket="$1"
    local storage="$2"
    local storage_lower
    storage_lower=$(echo "$storage" | tr '[:upper:]' '[:lower:]')
    local local_marker="${LOCAL_BACKUP_MARKER:-$LOG_DIR/last-local-backup-date}"
    local legacy_local_marker="$LOG_DIR/last-${storage_lower}-local-backup-date"
    local remote_marker="$LOG_DIR/last-${storage_lower}-backup-date"

    local was_nullglob=false
    shopt -q nullglob && was_nullglob=true
    shopt -s nullglob
    local local_backups=() candidate
    for candidate in "$BACKUP_DIR"/backup-*; do
        [[ -d "$candidate" ]] || continue
        [[ "$(basename "$candidate")" == *.tmp.* ]] && continue
        local_backups+=("$candidate")
    done
    $was_nullglob || shopt -u nullglob

    local local_summary="none"
    if (( ${#local_backups[@]} > 0 )); then
        local_summary=$(printf '%s\n' "${local_backups[@]}" | LC_ALL=C sort -r | head -n 3 | tr '\n' ' ')
    fi

    local last_local="never"
    if [[ -f "$local_marker" ]]; then
        last_local=$(cat "$local_marker" 2>/dev/null || echo never)
    elif [[ -f "$legacy_local_marker" ]]; then
        last_local=$(cat "$legacy_local_marker" 2>/dev/null || echo never)
    fi

    echo "📦 Local: ${local_summary}"
    echo "📦 ${storage}: $("$RCLONE" lsf "$bucket/_backups/" --dirs-only 2>/dev/null | LC_ALL=C sort -r | head -n 3 | tr '\n' ' ' || echo none)"
    echo "📅 Last local: ${last_local}"
    echo "📅 Last ${storage}: $(cat "$remote_marker" 2>/dev/null || echo never)"
}
