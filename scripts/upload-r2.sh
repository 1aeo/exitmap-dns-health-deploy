#!/usr/bin/env bash
# exitmap DNS Health - Upload to Cloudflare R2
# 
# Usage:
#   ./scripts/upload-r2.sh [source_dir]      # Sync entire directory
#   ./scripts/upload-r2.sh file1 file2 ...   # Upload specific files
#   ./scripts/upload-r2.sh --list-backups    # Show backup status
#   ./scripts/upload-r2.sh --force-backup    # Force backup today
#   ./scripts/upload-r2.sh --no-local-backup # Skip local backup (remote backup still runs)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/upload-common.sh"

_r2_local_backup_reported=false
report_r2_local_backup_result() {
    local outcome="$1" tmp_file
    [[ -n "${EXITMAP_LOCAL_BACKUP_RESULT_FILE:-}" ]] || return 0
    tmp_file="${EXITMAP_LOCAL_BACKUP_RESULT_FILE}.tmp.$$"
    ensure_dir "$(dirname "$EXITMAP_LOCAL_BACKUP_RESULT_FILE")" 2>/dev/null || return 0
    if printf '%s\n' "$outcome" > "$tmp_file" 2>/dev/null && mv -f -- "$tmp_file" "$EXITMAP_LOCAL_BACKUP_RESULT_FILE" 2>/dev/null; then
        _r2_local_backup_reported=true
    else
        rm -f -- "$tmp_file" 2>/dev/null || true
    fi
    return 0
}

cleanup_r2_exit() {
    cleanup_local_backup_staging
    if [[ "${_r2_local_backup_reported:-false}" != "true" ]]; then
        report_r2_local_backup_result failed || true
    fi
}
trap cleanup_r2_exit EXIT

# shellcheck disable=SC2034 # Read in sourced upload-common.sh
STORAGE_NAME="R2"
# R2 handles high parallelism well
TRANSFERS="${RCLONE_TRANSFERS:-128}"
# shellcheck disable=SC2034 # Read in sourced upload-common.sh
CHECKERS="${RCLONE_CHECKERS:-256}"

show_help() {
    echo "Usage: $0 [OPTIONS] [source_dir | files...]"
    echo ""
    echo "Options:"
    echo "  --list-backups      Show backup status"
    echo "  --force-backup      Force backup even if done today"
    echo "  --no-local-backup   Skip local backup step (still updates remote backup)"
    echo "  -h, --help          Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                      # Sync OUTPUT_DIR to R2"
    echo "  $0 ./results            # Sync specific directory"
    echo "  $0 latest.json files.json  # Upload specific files"
    exit 0
}

ACTION="sync"
FORCE=false
POSITIONAL=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list-backups)
            ACTION="list"
            shift
            ;;
        --force-backup)
            FORCE=true
            shift
            ;;
        --no-local-backup)
            # shellcheck disable=SC2034 # Read in sourced upload-common.sh
            SKIP_LOCAL_BACKUP=true
            shift
            ;;
        --help|-h)
            _r2_local_backup_reported=true
            show_help
            ;;
        --)
            shift
            POSITIONAL+=("$@")
            break
            ;;
        -*)
            log_error "Unknown option: $1"
            exit 2
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [[ "$ACTION" == "list" ]]; then
    _r2_local_backup_reported=true
    init_upload
    check_rclone
    ensure_r2_remote
    list_backups "${EXITMAP_R2_REMOTE}:${R2_BUCKET:?R2_BUCKET not set}" "R2"
    exit 0
fi

# Check if first positional arg is a file -> file upload mode
if [[ ${#POSITIONAL[@]} -gt 0 && -f "${POSITIONAL[0]}" ]]; then
    _r2_local_backup_reported=true
    init_upload
    check_rclone || exit 1
    ensure_r2_remote || exit 1
    BUCKET="${EXITMAP_R2_REMOTE}:${R2_BUCKET:?R2_BUCKET not set}"
    log "☁️  R2: ${R2_BUCKET}"
    upload_files "$BUCKET" "${POSITIONAL[@]}"
    exit 0
fi

init_upload "${POSITIONAL[0]:-}"

check_rclone || exit 1
[[ -d "$SOURCE_DIR" ]] || { log_error "Source not found: $SOURCE_DIR"; exit 1; }
ensure_r2_remote || exit 1

BUCKET="${EXITMAP_R2_REMOTE}:${R2_BUCKET:?R2_BUCKET not set}"
log "☁️  R2: ${R2_BUCKET} | $TRANSFERS transfers"

maybe_backup "$BUCKET" "$LOCAL_BACKUP_MARKER" local "$FORCE" || true
case "${_LOCAL_BACKUP_OUTCOME:-failed}" in
    created|already_done) report_r2_local_backup_result "$_LOCAL_BACKUP_OUTCOME" ;;
    skipped_*) report_r2_local_backup_result skipped ;;
    *) report_r2_local_backup_result failed ;;
esac
maybe_backup "$BUCKET" "$LOG_DIR/last-r2-backup-date" remote "$FORCE" || true
do_upload "$BUCKET"

log_success "R2 sync complete"
