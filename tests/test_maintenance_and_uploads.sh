#!/usr/bin/env bash
# Tests for backup coordination, rclone filters/error propagation, pruning,
# Tor temp cleanup, and log maintenance in exitmap-dns-health-deploy.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/exitmap-maint-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "PASS: $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo "FAIL: $1" >&2
    if [[ $# -gt 1 ]]; then
        echo "  Detail: $2" >&2
    fi
}

make_sandbox() {
    local name=$1
    local box="$WORK/$name"
    mkdir -p "$box/scripts" "$box/logs" "$box/backups" "$box/public" "$box/tmp" "$box/bin"
    cp "$REPO_DIR/scripts/common.sh" \
       "$REPO_DIR/scripts/upload-common.sh" \
       "$REPO_DIR/scripts/upload-do.sh" \
       "$REPO_DIR/scripts/upload-r2.sh" \
       "$REPO_DIR/scripts/prune-backups.sh" \
       "$REPO_DIR/scripts/run-dns-validation.sh" \
       "$box/scripts/"
    chmod +x "$box/scripts"/*.sh

    cat > "$box/bin/rclone" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
shift || true

echo "rclone $cmd $*" >> "${MOCK_RCLONE_LOG:?}"

case "$cmd" in
    listremotes)
        printf 'exitmap-r2:\nexitmap-spaces:\n'
        ;;
    config)
        exit 0
        ;;
    lsf)
        if [[ "${MOCK_R2_LSF_FAIL:-0}" == "1" ]]; then
            echo "mock lsf error" >&2
            exit 1
        fi
        printf '%b' "${MOCK_R2_BACKUPS:-}"
        ;;
    purge)
        target="${1:-}"
        if [[ "${MOCK_R2_PURGE_FAIL:-0}" == "1" ]] || [[ -n "${MOCK_R2_PURGE_FAIL_TARGET:-}" && "$target" == *"$MOCK_R2_PURGE_FAIL_TARGET"* ]]; then
            echo "mock purge error on $target" >&2
            exit 1
        fi
        ;;
    sync)
        src="${1:-}"
        dst="${2:-}"
        # Emit >10 lines to verify no SIGPIPE failure under pipefail
        for i in $(seq 1 15); do
            echo "Transferred line $i: $src -> $dst"
        done
        if [[ "$dst" == *"/_backups/"* ]]; then
            if [[ "${MOCK_FAIL_REMOTE:-0}" == "1" ]]; then
                echo "mock remote backup failure" >&2
                exit 1
            fi
        elif [[ "$dst" == *"/backups/backup-"* ]]; then
            if [[ "${MOCK_SLEEP_LOCAL:-0}" != "0" ]]; then
                sleep "${MOCK_SLEEP_LOCAL}"
            fi
            if [[ "${MOCK_FAIL_LOCAL:-0}" == "1" ]]; then
                mkdir -p "$dst"
                echo "partial" > "$dst/partial.json"
                echo "mock local backup failure" >&2
                exit 1
            fi
            mkdir -p "$dst"
            echo "{}" > "$dst/synced.json"
        else
            if [[ "${MOCK_FAIL_UPLOAD:-0}" == "1" ]]; then
                echo "mock live upload failure" >&2
                exit 1
            fi
        fi
        ;;
    copyto)
        if [[ "${MOCK_FAIL_UPLOAD:-0}" == "1" ]]; then
            echo "mock copyto failure" >&2
            exit 1
        fi
        echo "Transferred file $1 -> $2"
        ;;
esac
EOF
    chmod +x "$box/bin/rclone"
    echo "$box"
}

set_age_hours() {
    local target=$1
    local hours=$2
    python3 -c '
import os, sys, time
path, hrs = sys.argv[1], float(sys.argv[2])
t = time.time() - hrs * 3600.0
os.utime(path, (t, t))
' "$target" "$hours"
}

test_do_uploads_single_local_backup() {
    local box
    box=$(make_sandbox "do_uploads")
    echo '{"ok":true}' > "$box/public/latest.json"
    cat > "$box/config.env" <<EOF
RCLONE_PATH=$box/bin/rclone
DO_ENABLED=true
R2_ENABLED=true
DO_SPACES_BUCKET=test-do
DO_SPACES_KEY=k
DO_SPACES_SECRET=s
R2_BUCKET=test-r2
R2_ACCESS_KEY_ID=k
R2_SECRET_ACCESS_KEY=s
CLOUDFLARE_ACCOUNT_ID=acct
OUTPUT_DIR=$box/public
BACKUP_DIR=$box/backups
LOG_DIR=$box/logs
TMP_DIR=$box/tmp
EOF
    chmod 600 "$box/config.env"

    local rclone_log="$box/logs/rclone.log"
    # shellcheck disable=SC2016
    env EXITMAP_TEST_MODE=1 MOCK_RCLONE_LOG="$rclone_log" bash -c '
        source "$1"
        do_uploads
    ' _ "$box/scripts/run-dns-validation.sh" > "$box/logs/do_uploads.out" 2>&1

    local local_dirs=()
    shopt -s nullglob
    local_dirs=("$box/backups"/backup-*)
    shopt -u nullglob

    local local_syncs
    local_syncs=$(grep -c "/backups/backup-" "$rclone_log" || true)
    local remote_do remote_r2
    remote_do=$(grep -c "exitmap-spaces:test-do/_backups/" "$rclone_log" || true)
    remote_r2=$(grep -c "exitmap-r2:test-r2/_backups/" "$rclone_log" || true)

    if [[ ${#local_dirs[@]} -eq 1 && "$local_syncs" -eq 1 && "$remote_do" -eq 1 && "$remote_r2" -eq 1 ]]; then
        pass "do_uploads takes 1 local backup (R2) and updates both remote backups"
    else
        fail "do_uploads combined R2+DO" "dirs=${#local_dirs[@]} local_syncs=$local_syncs remote_do=$remote_do remote_r2=$remote_r2"
        return
    fi

    # Verify DO-only still takes a local backup on next fresh marker state
    rm -rf "$box/backups"/backup-* "$box/logs/last-local-backup-date" "$rclone_log"
    sed 's/R2_ENABLED=true/R2_ENABLED=false/' "$box/config.env" > "$box/config.env.tmp"
    mv "$box/config.env.tmp" "$box/config.env"
    chmod 600 "$box/config.env"

    # shellcheck disable=SC2016
    env EXITMAP_TEST_MODE=1 MOCK_RCLONE_LOG="$rclone_log" bash -c '
        source "$1"
        do_uploads
    ' _ "$box/scripts/run-dns-validation.sh" > "$box/logs/do_only.out" 2>&1

    local list_out
    list_out=$(MOCK_RCLONE_LOG="$rclone_log" "$box/scripts/upload-do.sh" --list-backups 2>&1)
    if [[ "$list_out" == *"Last local: "* && "$list_out" != *"Last local: never"* ]]; then
        pass "upload-do --list-backups reads unified last-local-backup-date marker"
    else
        fail "upload-do --list-backups" "got: $list_out"
        return
    fi

    shopt -s nullglob
    local_dirs=("$box/backups"/backup-*)
    shopt -u nullglob
    if [[ ${#local_dirs[@]} -eq 1 ]] && grep -q "exitmap-spaces:test-do" "$rclone_log"; then
        pass "do_uploads takes local backup from DO when R2_ENABLED=false"
    else
        fail "do_uploads DO-only" "dirs=${#local_dirs[@]}"
        return
    fi

    # Verify DO falls back to local backup when R2 fails pre-checks (missing R2_BUCKET/creds)
    rm -rf "$box/backups"/backup-* "$box/logs/last-local-backup-date" "$rclone_log"
    sed -e 's/R2_ENABLED=false/R2_ENABLED=true/' -e '/R2_ACCESS_KEY_ID/d' "$box/config.env" > "$box/config.env.tmp"
    mv "$box/config.env.tmp" "$box/config.env"
    chmod 600 "$box/config.env"

    # shellcheck disable=SC2016
    env EXITMAP_TEST_MODE=1 MOCK_RCLONE_LOG="$rclone_log" bash -c '
        source "$1"
        do_uploads
    ' _ "$box/scripts/run-dns-validation.sh" > "$box/logs/do_fallback.out" 2>&1

    shopt -s nullglob
    local_dirs=("$box/backups"/backup-*)
    shopt -u nullglob
    local do_local_syncs
    do_local_syncs=$(grep -c "sync exitmap-spaces:test-do .*/backups/backup-" "$rclone_log" || true)
    if [[ ${#local_dirs[@]} -eq 1 && "$do_local_syncs" -eq 1 && -f "$box/logs/last-local-backup-date" ]]; then
        pass "do_uploads falls back to DO local backup when R2 fails pre-checks"
    else
        fail "do_uploads R2 pre-check failure fallback" "dirs=${#local_dirs[@]} do_local_syncs=$do_local_syncs"
    fi
}

test_parallel_flock_dedup() {
    local box
    box=$(make_sandbox "parallel_flock")
    echo '{"ok":true}' > "$box/public/latest.json"
    cat > "$box/config.env" <<EOF
RCLONE_PATH=$box/bin/rclone
DO_SPACES_BUCKET=test-do
DO_SPACES_KEY=k
DO_SPACES_SECRET=s
R2_BUCKET=test-r2
R2_ACCESS_KEY_ID=k
R2_SECRET_ACCESS_KEY=s
CLOUDFLARE_ACCOUNT_ID=acct
OUTPUT_DIR=$box/public
BACKUP_DIR=$box/backups
LOG_DIR=$box/logs
EOF
    chmod 600 "$box/config.env"

    local rclone_log="$box/logs/rclone.log"
    MOCK_RCLONE_LOG="$rclone_log" MOCK_SLEEP_LOCAL=0.4 "$box/scripts/upload-r2.sh" > "$box/logs/r2.out" 2>&1 &
    local p1=$!
    MOCK_RCLONE_LOG="$rclone_log" MOCK_SLEEP_LOCAL=0.4 "$box/scripts/upload-do.sh" > "$box/logs/do.out" 2>&1 &
    local p2=$!
    local rc1=0 rc2=0
    wait "$p1" || rc1=$?
    wait "$p2" || rc2=$?
    if [[ $rc1 -ne 0 || $rc2 -ne 0 ]]; then
        fail "parallel flock dedup exit status" "rc1=$rc1 rc2=$rc2"
        return
    fi

    local local_dirs=()
    shopt -s nullglob
    local_dirs=("$box/backups"/backup-*)
    shopt -u nullglob
    local local_syncs
    local_syncs=$(grep -c "/backups/backup-" "$rclone_log" || true)

    if [[ ${#local_dirs[@]} -eq 1 && "$local_syncs" -eq 1 && -f "$box/logs/last-local-backup-date" ]]; then
        pass "parallel upload-r2 + upload-do without --no-local-backup still runs 1 local backup via flock + shared marker"
    else
        fail "parallel flock dedup" "dirs=${#local_dirs[@]} local_syncs=$local_syncs"
    fi
}

test_failure_cleanup_and_rclone_filters() {
    local box
    box=$(make_sandbox "failures_filters")
    echo '{"ok":true}' > "$box/public/latest.json"
    cat > "$box/config.env" <<EOF
RCLONE_PATH=$box/bin/rclone
R2_BUCKET=test-r2
R2_ACCESS_KEY_ID=k
R2_SECRET_ACCESS_KEY=s
CLOUDFLARE_ACCOUNT_ID=acct
OUTPUT_DIR=$box/public
BACKUP_DIR=$box/backups
LOG_DIR=$box/logs
EOF
    chmod 600 "$box/config.env"

    local rclone_log="$box/logs/rclone.log"

    # 1. Local and remote backup failures must NOT write markers and must remove .tmp.*
    MOCK_RCLONE_LOG="$rclone_log" MOCK_FAIL_LOCAL=1 MOCK_FAIL_REMOTE=1 \
        "$box/scripts/upload-r2.sh" > "$box/logs/fail_backup.out" 2>&1

    local leftover=()
    shopt -s nullglob
    leftover=("$box/backups"/backup-*)
    shopt -u nullglob

    if [[ ${#leftover[@]} -eq 0 && ! -f "$box/logs/last-local-backup-date" && ! -f "$box/logs/last-r2-backup-date" ]]; then
        pass "failed local/remote backups clean .tmp.* staging and leave markers unwritten"
    else
        fail "failed backup cleanup" "leftover=${#leftover[@]}"
        return
    fi

    # 2. Live upload must use ordered --filter rules (no mixed --include/--exclude)
    local upload_sync_line
    upload_sync_line=$(grep "rclone sync $box/public exitmap-r2:test-r2 " "$rclone_log" || true)
    if [[ "$upload_sync_line" == *"--filter - _backups/** --filter - index.html --filter + *.json --filter + archives/*.tar.gz --filter - *"* ]] && \
       [[ "$upload_sync_line" != *"--include"* && "$upload_sync_line" != *"--exclude"* ]]; then
        pass "do_upload uses ordered --filter flags without mixed --include/--exclude"
    else
        fail "do_upload --filter flags" "got line: $upload_sync_line"
        return
    fi

    # 3. Failed do_upload must exit non-zero despite >10 lines of rclone output
    if MOCK_RCLONE_LOG="$rclone_log" MOCK_FAIL_UPLOAD=1 "$box/scripts/upload-r2.sh" > "$box/logs/fail_upload.out" 2>&1; then
        fail "do_upload failure exit code" "expected non-zero exit"
    else
        pass "do_upload propagates non-zero exit code without SIGPIPE masking"
    fi
}

test_prune_backups() {
    local box
    box=$(make_sandbox "prune")
    cat > "$box/config.env" <<EOF
RCLONE_PATH=$box/bin/rclone
R2_BUCKET=test-r2
BACKUP_DIR=$box/backups
KEEP_BACKUPS=99
EOF
    chmod 600 "$box/config.env"

    # Create 10 local complete backups (01..10), 1 fresh .tmp, 1 stale .tmp (>24h)
    for d in $(seq -w 1 10); do
        mkdir -p "$box/backups/backup-2026-11-${d}_000501"
    done
    mkdir -p "$box/backups/backup-2026-11-11_000501.tmp.123"
    mkdir -p "$box/backups/backup-2026-11-01_000501.tmp.999"
    set_age_hours "$box/backups/backup-2026-11-01_000501.tmp.999" 30

    local r2_list=""
    for d in $(seq -w 1 8); do
        r2_list="${r2_list}2026-11-${d}_000501/\n"
    done

    local rclone_log="$box/logs/rclone.log"

    # Validation fail-closed tests
    local rc=0
    KEEP_BACKUPS=0 "$box/scripts/prune-backups.sh" >/dev/null 2>&1 || rc=$?
    if [[ $rc -eq 2 ]]; then
        pass "prune-backups rejects invalid KEEP_BACKUPS=0 with exit 2"
    else
        fail "prune-backups invalid KEEP_BACKUPS" "expected exit 2, got $rc"
        return
    fi

    rc=0
    LOCAL_KEEP_BACKUPS=abc "$box/scripts/prune-backups.sh" >/dev/null 2>&1 || rc=$?
    if [[ $rc -eq 2 ]]; then
        pass "prune-backups rejects non-numeric LOCAL_KEEP_BACKUPS with exit 2"
    else
        fail "prune-backups invalid LOCAL_KEEP_BACKUPS" "expected exit 2, got $rc"
        return
    fi

    # Safety buffer: 8 R2 backups with KEEP_BACKUPS=6 (threshold=8) must skip R2 purge;
    # 10 local backups with LOCAL_KEEP_BACKUPS=8 (threshold=10) must skip local purge;
    # --dry-run must preserve even stale .tmp.
    MOCK_RCLONE_LOG="$rclone_log" MOCK_R2_BACKUPS="$r2_list" KEEP_BACKUPS=6 LOCAL_KEEP_BACKUPS=8 \
        "$box/scripts/prune-backups.sh" --dry-run > "$box/logs/prune_dry.out" 2>&1
    if [[ -d "$box/backups/backup-2026-11-01_000501" && -d "$box/backups/backup-2026-11-01_000501.tmp.999" ]] && \
       ! grep -q "rclone purge" "$rclone_log"; then
        pass "prune-backups honors safety buffer (+2) and --dry-run"
    else
        fail "prune-backups safety buffer / dry-run"
        return
    fi

    # Env overrides beat config.env (KEEP_BACKUPS=99), independent LOCAL_KEEP_BACKUPS=4 vs KEEP_BACKUPS=3
    MOCK_RCLONE_LOG="$rclone_log" MOCK_R2_BACKUPS="$r2_list" KEEP_BACKUPS=3 LOCAL_KEEP_BACKUPS=4 \
        "$box/scripts/prune-backups.sh" > "$box/logs/prune_real.out" 2>&1

    local remaining_local=()
    shopt -s nullglob
    remaining_local=("$box/backups"/backup-2026-11-*_000501)
    shopt -u nullglob
    local r2_purges
    r2_purges=$(grep -c "rclone purge exitmap-r2:test-r2/_backups/" "$rclone_log" || true)

    if [[ ${#remaining_local[@]} -eq 4 ]] && \
       [[ -d "$box/backups/backup-2026-11-10_000501" ]] && \
       [[ -d "$box/backups/backup-2026-11-07_000501" ]] && \
       [[ ! -d "$box/backups/backup-2026-11-06_000501" ]] && \
       [[ -d "$box/backups/backup-2026-11-11_000501.tmp.123" ]] && \
       [[ ! -d "$box/backups/backup-2026-11-01_000501.tmp.999" ]] && \
       [[ "$r2_purges" -eq 5 ]]; then
        pass "prune-backups overrides config.env, enforces LOCAL_KEEP_BACKUPS & KEEP_BACKUPS independently, keeps fresh .tmp.*, removes stale .tmp.*"
    else
        fail "prune-backups pruning counts" "local=${#remaining_local[@]} r2_purges=$r2_purges"
        return
    fi

    # R2 listing failure must return non-zero
    if MOCK_RCLONE_LOG="$rclone_log" MOCK_R2_LSF_FAIL=1 KEEP_BACKUPS=3 LOCAL_KEEP_BACKUPS=4 \
        "$box/scripts/prune-backups.sh" >/dev/null 2>&1; then
        fail "prune-backups R2 error propagation" "expected non-zero exit"
    else
        pass "prune-backups exits non-zero when R2 listing fails"
    fi
}

test_log_maintenance_and_tor_cleanup() {
    local box
    box=$(make_sandbox "logs_tor")
    cat > "$box/config.env" <<EOF
OUTPUT_DIR=$box/public
LOG_DIR=$box/logs
TMP_DIR=$box/tmp
LOG_COMPRESS_DAYS=30
CRON_LOG_MAX_BYTES=64
CRON_LOG_ARCHIVES=2
EOF
    chmod 600 "$box/config.env"

    echo "old validation output" > "$box/logs/validation_2026-09-01_00-05-01.log"
    echo "recent validation output" > "$box/logs/validation_2026-11-20_00-05-01.log"
    set_age_hours "$box/logs/validation_2026-09-01_00-05-01.log" $((35 * 24))

    # Populate cron.log and prune.log (>64 bytes) and hold an open FD pointing at cron.log's inode
    printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_initial\n' > "$box/logs/cron.log"
    printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_prune\n' > "$box/logs/prune.log"
    printf 'existing archive 1' | gzip -c > "$box/logs/cron.log.1.gz"
    exec 8>>"$box/logs/cron.log"

    # Populate tor_cache and per-wave / stale tor dirs
    mkdir -p "$box/tmp/tor_cache" "$box/tmp/exitmap_tor_w1_1" "$box/tmp/exitmap_tor_w20_4" "$box/tmp/exitmap_tor_99"
    echo "consensus" > "$box/tmp/tor_cache/cached-consensus"
    echo "dup" > "$box/tmp/exitmap_tor_w20_4/cached-consensus"
    echo "stale" > "$box/tmp/exitmap_tor_99/cached-consensus"
    set_age_hours "$box/tmp/exitmap_tor_99" 30

    # shellcheck disable=SC2016
    env EXITMAP_TEST_MODE=1 bash -c '
        source "$1"
        touch "$UNIFIED_LOG"
        maintain_logs
        cleanup_all
    ' _ "$box/scripts/run-dns-validation.sh" > "$box/logs/maint.out" 2>&1

    # Write after rotation through the already-open cron FD
    echo "post-rotation-line" >&8
    exec 8>&-

    local archived1_content
    archived1_content=$(gzip -dc "$box/logs/cron.log.1.gz" 2>/dev/null || true)

    if [[ -f "$box/logs/validation_2026-09-01_00-05-01.log.gz" ]] && \
       [[ ! -f "$box/logs/validation_2026-09-01_00-05-01.log" ]] && \
       gzip -t "$box/logs/validation_2026-09-01_00-05-01.log.gz" && \
       [[ -f "$box/logs/validation_2026-11-20_00-05-01.log" ]]; then
        pass "maintain_logs losslessly compresses validation_*.log older than LOG_COMPRESS_DAYS"
    else
        fail "maintain_logs validation_*.log compression"
        return
    fi

    if [[ -f "$box/logs/cron.log.2.gz" && -f "$box/logs/cron.log.1.gz" && ! -f "$box/logs/cron.log.3.gz" ]] && \
       [[ -f "$box/logs/prune.log.1.gz" ]] && \
       [[ "$archived1_content" == *"_initial"* ]] && \
       [[ "$(cat "$box/logs/cron.log")" == "post-rotation-line" ]]; then
        pass "maintain_logs rotates cron.log & prune.log via copy-truncate preserving open cron FD and max archives"
    else
        fail "maintain_logs copy-truncate rotation" "cron.log=$(cat "$box/logs/cron.log" 2>/dev/null || true)"
        return
    fi

    if [[ ! -d "$box/tmp/exitmap_tor_w1_1" && ! -d "$box/tmp/exitmap_tor_w20_4" && ! -d "$box/tmp/exitmap_tor_99" ]] && \
       [[ -f "$box/tmp/tor_cache/cached-consensus" ]]; then
        pass "cleanup_all removes per-wave and stale exitmap_tor_* dirs while preserving tor_cache"
    else
        fail "cleanup_all wave/stale tor cleanup"
        return
    fi

    # Regression check: TMP_DIR named exitmap_tor_* must NEVER delete itself (requires -mindepth 1)
    local self_box="$WORK/exitmap_tor_self_tmp"
    mkdir -p "$self_box/sub"
    set_age_hours "$self_box" 30
    # shellcheck disable=SC2016
    env EXITMAP_TEST_MODE=1 TMP_DIR="$self_box" LOG_DIR="$box/logs" OUTPUT_DIR="$box/public" bash -c '
        source "$1"
        cleanup_all
    ' _ "$box/scripts/run-dns-validation.sh" >/dev/null 2>&1
    if [[ -d "$self_box" ]]; then
        pass "cleanup_all preserves TMP_DIR itself when basename matches exitmap_tor_*"
    else
        fail "cleanup_all -mindepth 1 self-deletion guard" "TMP_DIR $self_box was deleted"
        return
    fi

    # Regression check: validate_config_values rejects 0 and leading-zero cron log settings
    for bad_cfg in "CRON_LOG_MAX_BYTES=0" "CRON_LOG_MAX_BYTES=008388608" "CRON_LOG_ARCHIVES=0" "KEEP_BACKUPS=0"; do
        local var_name="${bad_cfg%%=*}"
        local val_err
        # shellcheck disable=SC2016
        if val_err=$(bash -c '
            source "$1"
            export "$2"
            validate_config_values
        ' _ "$box/scripts/common.sh" "$bad_cfg" 2>&1); then
            fail "validate_config_values $bad_cfg" "expected validation failure"
            return
        fi
        if [[ "$val_err" != *"$var_name"* ]]; then
            fail "validate_config_values $bad_cfg error text" "got: $val_err"
            return
        fi
    done
    pass "validate_config_values rejects zero and leading-zero positive-integer settings by name"

    # Regression check: failed gzip in rotate_log_copytruncate preserves original log and archive
    local fail_bin="$box/fail-gzip-bin"
    mkdir -p "$fail_bin"
    printf '#!/usr/bin/env bash\nexit 1\n' > "$fail_bin/gzip"
    chmod +x "$fail_bin/gzip"
    printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_keep_intact\n' > "$box/logs/keep.log"
    # shellcheck disable=SC2016
    PATH="$fail_bin:$PATH" env EXITMAP_TEST_MODE=1 bash -c '
        source "$1"
        rotate_log_copytruncate "$2" 64 2
    ' _ "$box/scripts/run-dns-validation.sh" "$box/logs/keep.log" >/dev/null 2>&1
    if grep -q "_keep_intact" "$box/logs/keep.log"; then
        pass "rotate_log_copytruncate preserves original log intact when gzip fails"
    else
        fail "rotate_log_copytruncate gzip failure preservation"
    fi
}

echo "Running exitmap-dns-health-deploy maintenance & upload tests..."
test_do_uploads_single_local_backup
test_parallel_flock_dedup
test_failure_cleanup_and_rclone_filters
test_prune_backups
test_log_maintenance_and_tor_cleanup

echo ""
echo "Summary: $TESTS_PASSED passed, $TESTS_FAILED failed"
[[ $TESTS_FAILED -eq 0 ]]
