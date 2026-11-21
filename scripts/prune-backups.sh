#!/usr/bin/env bash
# exitmap DNS Health - Prune Old Backups
# Removes old local and R2 backups (keeps newest N + safety buffer before pruning).
#
# Usage:
#   ./scripts/prune-backups.sh              # Prune old backups
#   ./scripts/prune-backups.sh --dry-run    # Show what would be pruned

set -euo pipefail

DRY_RUN=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Prune old local and R2 backups while retaining at least KEEP_BACKUPS snapshots.

Options:
  --dry-run    Show what would be removed without deleting anything
  -h, --help   Show this help
EOF
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Capture caller environment overrides before load_config sources config.env
PRUNE_OVERRIDE_VARS=(BACKUP_DIR LOG_DIR LOCAL_BACKUP_LOCK_FILE R2_BUCKET R2_ENABLED RCLONE_PATH KEEP_BACKUPS LOCAL_KEEP_BACKUPS)
PRUNE_OVERRIDE_STATES=()
PRUNE_OVERRIDE_VALUES=()
for _var in "${PRUNE_OVERRIDE_VARS[@]}"; do
    if [[ -n "${!_var+x}" ]]; then
        PRUNE_OVERRIDE_STATES+=(1)
        PRUNE_OVERRIDE_VALUES+=("${!_var}")
    else
        PRUNE_OVERRIDE_STATES+=(0)
        PRUNE_OVERRIDE_VALUES+=("")
    fi
done

init_paths
load_config || true

for _i in "${!PRUNE_OVERRIDE_VARS[@]}"; do
    if [[ "${PRUNE_OVERRIDE_STATES[$_i]}" == "1" ]]; then
        printf -v "${PRUNE_OVERRIDE_VARS[$_i]}" '%s' "${PRUNE_OVERRIDE_VALUES[$_i]}"
    fi
done

BACKUP_DIR="${BACKUP_DIR:-$DEPLOY_DIR/backups}"
LOG_DIR="${LOG_DIR:-$DEPLOY_DIR/logs}"
LOCAL_BACKUP_LOCK_FILE="${LOCAL_BACKUP_LOCK_FILE:-$LOG_DIR/.local-backup.lock}"
RCLONE="${RCLONE_PATH:-$(command -v rclone 2>/dev/null || echo "$HOME/bin/rclone")}"
KEEP_BACKUPS="${KEEP_BACKUPS:-7}"
LOCAL_KEEP_BACKUPS="${LOCAL_KEEP_BACKUPS:-$KEEP_BACKUPS}"
SAFETY_BUFFER=2

prune_log() { echo "[PRUNE] [$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
count_lines() { local c; c=$(grep -c . <<< "$1" 2>/dev/null) || c=0; echo "$c"; }

if [[ ! "$KEEP_BACKUPS" =~ ^[1-9][0-9]*$ ]]; then
    prune_log "❌ Invalid KEEP_BACKUPS=$KEEP_BACKUPS (must be a positive integer)"
    exit 2
fi
if [[ ! "$LOCAL_KEEP_BACKUPS" =~ ^[1-9][0-9]*$ ]]; then
    prune_log "❌ Invalid LOCAL_KEEP_BACKUPS=$LOCAL_KEEP_BACKUPS (must be a positive integer)"
    exit 2
fi

LOCAL_PRUNE_THRESHOLD=$((LOCAL_KEEP_BACKUPS + SAFETY_BUFFER))
R2_PRUNE_THRESHOLD=$((KEEP_BACKUPS + SAFETY_BUFFER))

prune_local() {
    [[ -d "$BACKUP_DIR" ]] || return 0
    if [[ ! -r "$BACKUP_DIR" || ! -x "$BACKUP_DIR" ]]; then
        prune_log "❌ Local backup directory not readable: $BACKUP_DIR"
        return 1
    fi

    # Remove stale incomplete staging directories older than 24 hours only when
    # no local backup holds LOCAL_BACKUP_LOCK_FILE (rclone writes into subdirs).
    local run_stale_cleanup=true prune_lock_open=false
    if [[ -f "$LOCAL_BACKUP_LOCK_FILE" ]] && command -v flock >/dev/null 2>&1; then
        exec 7>"$LOCAL_BACKUP_LOCK_FILE"
        prune_lock_open=true
        if ! flock -n 7; then
            exec 7>&-
            prune_lock_open=false
            run_stale_cleanup=false
            prune_log "Skipping stale temp cleanup (local backup lock is held)"
        fi
    fi

    if [[ "$run_stale_cleanup" == "true" ]]; then
        while IFS= read -r -d '' stale_tmp; do
            if $DRY_RUN; then
                prune_log "[DRY-RUN] Would remove stale temp: $(basename "$stale_tmp")"
            else
                prune_log "Removing stale temp: $(basename "$stale_tmp")"
                if ! rm -rf -- "$stale_tmp"; then
                    if [[ "$prune_lock_open" == "true" ]]; then
                        exec 7>&-
                    fi
                    prune_log "❌ Failed to remove stale temp: $stale_tmp"
                    return 1
                fi
            fi
        done < <(find "$BACKUP_DIR" -maxdepth 1 -type d -name 'backup-*.tmp.*' -mmin +1440 -print0 2>/dev/null)
    fi

    if [[ "$prune_lock_open" == "true" ]]; then
        exec 7>&-
    fi

    # Enumerate completed backup directories only (ignore active *.tmp.*)
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

    local count=${#local_backups[@]}
    if [[ "$count" -le "$LOCAL_PRUNE_THRESHOLD" ]]; then
        prune_log "Local: $count backups (need >$LOCAL_PRUNE_THRESHOLD to prune)"
        return 0
    fi

    local sorted_all to_delete
    sorted_all=$(printf '%s\n' "${local_backups[@]}" | LC_ALL=C sort -r)
    to_delete=$(printf '%s\n' "$sorted_all" | tail -n +$((LOCAL_KEEP_BACKUPS + 1)))
    prune_log "Local: $count found, pruning $(count_lines "$to_delete") (keeping $LOCAL_KEEP_BACKUPS)..."

    local local_failed=false
    while IFS= read -r dir; do
        [[ -z "$dir" ]] && continue
        local size
        size=$(du -sh "$dir" 2>/dev/null | cut -f1) || size="?"
        if $DRY_RUN; then
            prune_log "[DRY-RUN] Would remove: $(basename "$dir") ($size)"
        else
            if rm -rf -- "$dir"; then
                prune_log "  Removed: $(basename "$dir") ($size)"
            else
                prune_log "❌ Failed to remove local backup: $dir"
                local_failed=true
            fi
        fi
    done <<< "$to_delete"

    if $local_failed; then
        return 1
    fi
    $DRY_RUN || prune_log "✅ Local prune done"
}

prune_r2() {
    [[ "${R2_ENABLED:-true}" == "true" && -n "${R2_BUCKET:-}" && -x "$RCLONE" ]] || return 0

    local bucket="exitmap-r2:${R2_BUCKET}"
    local all r2_err_file
    r2_err_file=$(mktemp "${TMPDIR:-/tmp}/exitmap-prune-r2.XXXXXX")
    if ! all=$("$RCLONE" lsf "$bucket/_backups/" --dirs-only 2>"$r2_err_file"); then
        local r2_err
        r2_err=$(cat "$r2_err_file" 2>/dev/null || true)
        rm -f -- "$r2_err_file"
        prune_log "❌ R2 backup listing failed${r2_err:+: $r2_err}"
        return 1
    fi
    rm -f -- "$r2_err_file"

    local count
    count=$(count_lines "$all")
    if [[ "$count" -le "$R2_PRUNE_THRESHOLD" ]]; then
        prune_log "R2: $count backups (need >$R2_PRUNE_THRESHOLD to prune)"
        return 0
    fi

    local to_delete
    to_delete=$(printf '%s\n' "$all" | LC_ALL=C sort -r | tail -n +$((KEEP_BACKUPS + 1)))
    prune_log "R2: $count found, pruning $(count_lines "$to_delete") (keeping $KEEP_BACKUPS)..."

    local r2_failed=false
    while IFS= read -r backup; do
        [[ -z "$backup" ]] && continue
        if $DRY_RUN; then
            prune_log "[DRY-RUN] Would remove: R2/_backups/$backup"
        else
            if "$RCLONE" purge "$bucket/_backups/$backup" 2>&1; then
                prune_log "  Removed: R2/_backups/$backup"
            else
                prune_log "❌ Failed to remove: R2/_backups/$backup"
                r2_failed=true
            fi
        fi
    done <<< "$to_delete"

    if $r2_failed; then
        return 1
    fi
    $DRY_RUN || prune_log "✅ R2 prune done"
}

prune_log "Starting (keep_r2=$KEEP_BACKUPS, keep_local=$LOCAL_KEEP_BACKUPS, dry_run=$DRY_RUN)..."
prune_status=0
prune_local || prune_status=1
prune_r2 || prune_status=1
prune_log "Finished"
exit "$prune_status"
