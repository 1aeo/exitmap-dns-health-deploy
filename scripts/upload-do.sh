#!/usr/bin/env bash
# exitmap DNS Health - Upload to DigitalOcean Spaces
# 
# Usage:
#   ./scripts/upload-do.sh [source_dir]      # Sync entire directory
#   ./scripts/upload-do.sh file1 file2 ...   # Upload specific files
#   ./scripts/upload-do.sh --list-backups    # Show backup status
#   ./scripts/upload-do.sh --force-backup    # Force backup today
#   ./scripts/upload-do.sh --no-local-backup # Skip local backup (remote backup still runs)
#   ./scripts/upload-do.sh --local-backup-only [source_dir]  # Local backup only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/upload-common.sh"
trap cleanup_local_backup_staging EXIT

# shellcheck disable=SC2034 # Read in sourced upload-common.sh
STORAGE_NAME="DO"
# DO Spaces has rate limits - use conservative settings
TRANSFERS="${DO_RCLONE_TRANSFERS:-56}"
# shellcheck disable=SC2034 # Read in sourced upload-common.sh
CHECKERS="${DO_RCLONE_CHECKERS:-80}"

show_help() {
    echo "Usage: $0 [OPTIONS] [source_dir | files...]"
    echo ""
    echo "Options:"
    echo "  --list-backups      Show backup status"
    echo "  --force-backup      Force backup even if done today"
    echo "  --no-local-backup   Skip local backup step (still updates remote backup)"
    echo "  --local-backup-only Take local backup from DO Spaces only"
    echo "  -h, --help          Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                      # Sync OUTPUT_DIR to DO Spaces"
    echo "  $0 ./results            # Sync specific directory"
    echo "  $0 latest.json files.json  # Upload specific files"
    exit 0
}

ACTION="sync"
FORCE=false
LOCAL_BACKUP_ONLY=false
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
        --local-backup-only)
            LOCAL_BACKUP_ONLY=true
            shift
            ;;
        --help|-h)
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
    init_upload
    check_rclone
    ensure_do_remote
    list_backups "${EXITMAP_DO_REMOTE}:${DO_SPACES_BUCKET:?DO_SPACES_BUCKET not set}" "DO"
    exit 0
fi

# Check if first positional arg is a file -> file upload mode
if [[ ${#POSITIONAL[@]} -gt 0 && -f "${POSITIONAL[0]}" ]]; then
    init_upload
    check_rclone || exit 1
    ensure_do_remote || exit 1
    BUCKET="${EXITMAP_DO_REMOTE}:${DO_SPACES_BUCKET:?DO_SPACES_BUCKET not set}"
    log "☁️  DO Spaces: ${DO_SPACES_BUCKET}"
    upload_files "$BUCKET" "${POSITIONAL[@]}"
    exit 0
fi

init_upload "${POSITIONAL[0]:-}"

if [[ "$LOCAL_BACKUP_ONLY" == "true" ]]; then
    check_rclone || exit 1
    ensure_do_remote || exit 1
    BUCKET="${EXITMAP_DO_REMOTE}:${DO_SPACES_BUCKET:?DO_SPACES_BUCKET not set}"
    log "☁️  DO Spaces fallback local backup: ${DO_SPACES_BUCKET}"
    maybe_backup "$BUCKET" "$LOCAL_BACKUP_MARKER" local "$FORCE" || true
    if [[ "${_LOCAL_BACKUP_OUTCOME:-failed}" == "created" || "${_LOCAL_BACKUP_OUTCOME:-failed}" == "already_done" ]]; then
        log_success "DO Spaces local backup complete"
    fi
    exit 0
fi

check_rclone || exit 1
[[ -d "$SOURCE_DIR" ]] || { log_error "Source not found: $SOURCE_DIR"; exit 1; }
ensure_do_remote || exit 1

BUCKET="${EXITMAP_DO_REMOTE}:${DO_SPACES_BUCKET:?DO_SPACES_BUCKET not set}"
log "☁️  DO Spaces: ${DO_SPACES_BUCKET} | $TRANSFERS transfers"

maybe_backup "$BUCKET" "$LOCAL_BACKUP_MARKER" local "$FORCE" || true
maybe_backup "$BUCKET" "$LOG_DIR/last-do-backup-date" remote "$FORCE" || true
do_upload "$BUCKET"

log_success "DO Spaces sync complete"
