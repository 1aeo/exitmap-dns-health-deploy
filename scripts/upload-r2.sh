#!/usr/bin/env bash
# exitmap DNS Health - Upload to Cloudflare R2
# 
# Usage:
#   ./scripts/upload-r2.sh [source_dir]      # Sync entire directory
#   ./scripts/upload-r2.sh file1 file2 ...   # Upload specific files
#   ./scripts/upload-r2.sh --list-backups    # Show backup status
#   ./scripts/upload-r2.sh --force-backup    # Force backup today

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/upload-common.sh"

STORAGE_NAME="R2"
# R2 handles high parallelism well
TRANSFERS="${RCLONE_TRANSFERS:-128}"
CHECKERS="${RCLONE_CHECKERS:-256}"

show_help() {
    echo "Usage: $0 [OPTIONS] [source_dir | files...]"
    echo ""
    echo "Options:"
    echo "  --list-backups    Show backup status"
    echo "  --force-backup    Force backup even if done today"
    echo "  -h, --help        Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                      # Sync OUTPUT_DIR to R2"
    echo "  $0 ./results            # Sync specific directory"
    echo "  $0 latest.json files.json  # Upload specific files"
    exit 0
}

case "${1:-}" in
    --list-backups)
        init_upload
        check_rclone
        ensure_r2_remote
        list_backups "${EXITMAP_R2_REMOTE}:${R2_BUCKET:?R2_BUCKET not set}" "R2"
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
            ensure_r2_remote || exit 1
            BUCKET="${EXITMAP_R2_REMOTE}:${R2_BUCKET:?R2_BUCKET not set}"
            log "☁️  R2: ${R2_BUCKET}"
            upload_files "$BUCKET" "$@"
            exit 0
        fi
        init_upload "${1:-}"
        ;;
esac

check_rclone || exit 1
[[ -d "$SOURCE_DIR" ]] || { log_error "Source not found: $SOURCE_DIR"; exit 1; }
ensure_r2_remote || exit 1

BUCKET="${EXITMAP_R2_REMOTE}:${R2_BUCKET:?R2_BUCKET not set}"
log "☁️  R2: ${R2_BUCKET} | $TRANSFERS transfers"

maybe_backup "$BUCKET" "$LOG_DIR/last-r2-local-backup-date" local "$FORCE" || true
maybe_backup "$BUCKET" "$LOG_DIR/last-r2-backup-date" remote "$FORCE" || true
do_upload "$BUCKET"

log_success "R2 sync complete"
