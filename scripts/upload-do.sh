#!/usr/bin/env bash
# exitmap DNS Health - Upload to DigitalOcean Spaces
# 
# Usage:
#   ./scripts/upload-do.sh [source_dir]      # Sync entire directory
#   ./scripts/upload-do.sh file1 file2 ...   # Upload specific files
#   ./scripts/upload-do.sh --list-backups    # Show backup status
#   ./scripts/upload-do.sh --force-backup    # Force backup today

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/upload-common.sh"

STORAGE_NAME="DO"
# DO Spaces has rate limits - use conservative settings
TRANSFERS="${DO_RCLONE_TRANSFERS:-56}"
CHECKERS="${DO_RCLONE_CHECKERS:-80}"

show_help() {
    echo "Usage: $0 [OPTIONS] [source_dir | files...]"
    echo ""
    echo "Options:"
    echo "  --list-backups    Show backup status"
    echo "  --force-backup    Force backup even if done today"
    echo "  -h, --help        Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                      # Sync OUTPUT_DIR to DO Spaces"
    echo "  $0 ./results            # Sync specific directory"
    echo "  $0 latest.json files.json  # Upload specific files"
    exit 0
}

case "${1:-}" in
    --list-backups)
        init_upload
        check_rclone
        ensure_do_remote
        list_backups "${EXITMAP_DO_REMOTE}:${DO_SPACES_BUCKET:?DO_SPACES_BUCKET not set}" "DO"
        exit 0
        ;;
    --help|-h)
        show_help
        ;;
    --force-backup)
        FORCE=true
        shift
        init_upload "${1:-}"
        ;;
    *)
        FORCE=false
        # Check if first arg is a directory or file
        if [[ -n "${1:-}" && -f "$1" ]]; then
            # File mode - upload specific files
            init_upload
            check_rclone || exit 1
            ensure_do_remote || exit 1
            BUCKET="${EXITMAP_DO_REMOTE}:${DO_SPACES_BUCKET:?DO_SPACES_BUCKET not set}"
            log "☁️  DO Spaces: ${DO_SPACES_BUCKET}"
            upload_files "$BUCKET" "$@"
            exit 0
        fi
        init_upload "${1:-}"
        ;;
esac

check_rclone || exit 1
[[ -d "$SOURCE_DIR" ]] || { log_error "Source not found: $SOURCE_DIR"; exit 1; }
ensure_do_remote || exit 1

BUCKET="${EXITMAP_DO_REMOTE}:${DO_SPACES_BUCKET:?DO_SPACES_BUCKET not set}"
log "☁️  DO Spaces: ${DO_SPACES_BUCKET} | $TRANSFERS transfers"

maybe_backup "$BUCKET" "$LOG_DIR/last-do-local-backup-date" local "$FORCE" || true
maybe_backup "$BUCKET" "$LOG_DIR/last-do-backup-date" remote "$FORCE" || true
do_upload "$BUCKET"

log_success "DO Spaces sync complete"
