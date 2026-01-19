#!/bin/bash
# exitmap DNS Health Validation Runner
#
# Modes:
#   Single:           Default, one instance scans all relays
#   Cross-validation: N instances scan ALL relays, pass if ANY succeeds
#   Split:            N instances divide relays, merge results
#
# Usage:
#   ./scripts/run_dns_validation.sh                    # Single instance
#   ./scripts/run_dns_validation.sh -c 2               # Cross-validate with 2 instances
#   ./scripts/run_dns_validation.sh --cross-validate 3 # Cross-validate with 3 instances
#   ./scripts/run_dns_validation.sh -s 4               # Split relays among 4 instances
#   ./scripts/run_dns_validation.sh --split 2          # Split relays among 2 instances
#
# Configuration:
#   Copy config.env.example to config.env and customize settings.

set -euo pipefail

# Ensure sufficient file descriptors for parallel circuit operations
# (4 instances × 128 circuits × overhead = ~5k needed, 128k provides large safety margin)
ulimit -n 131072 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
# Exitmap is a sibling directory to the deploy dir
EXITMAP_DIR="${EXITMAP_DIR:-$(dirname "$DEPLOY_DIR")/exitmap}"

# Parse command line arguments
MODE="single"
INSTANCE_COUNT=1

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--cross-validate)
            MODE="cross-validate"
            INSTANCE_COUNT="${2:-2}"
            shift 2
            ;;
        -s|--split)
            MODE="split"
            INSTANCE_COUNT="${2:-2}"
            shift 2
            ;;
        -p|--parallel)
            # Legacy: treat --parallel as --cross-validate 2
            MODE="cross-validate"
            INSTANCE_COUNT=2
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -c, --cross-validate N   Cross-validation mode with N instances"
            echo "                           (all scan all relays, pass if any succeeds)"
            echo "  -s, --split N            Split mode with N instances"
            echo "                           (divide relays among instances)"
            echo "  -p, --parallel           Legacy: same as --cross-validate 2"
            echo "  -h, --help               Show this help"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Load configuration
if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    source "$DEPLOY_DIR/config.env"
elif [[ -f "$EXITMAP_DIR/config.env" ]]; then
    source "$EXITMAP_DIR/config.env"
else
    echo "Warning: config.env not found. Using defaults."
fi

# Default configuration
# Use DEPLOY_DIR for outputs (not EXITMAP_DIR which may not exist as expected)
OUTPUT_DIR="${OUTPUT_DIR:-$DEPLOY_DIR/public}"
LOG_DIR="${LOG_DIR:-$DEPLOY_DIR/logs}"
TMP_DIR="${TMP_DIR:-$DEPLOY_DIR/tmp}"
BUILD_DELAY="${BUILD_DELAY:-0}"
DELAY_NOISE="${DELAY_NOISE:-0}"

# Auto-scale MAX_PENDING_CIRCUITS based on instance count to prevent process explosion
# Each exitmap instance spawns a multiprocessing.Process PER circuit, so:
# - Single instance: 128 circuits = ~128 processes
# - 4 instances × 128 = 512 processes (too many, causes OOM)
# Solution: Scale down per-instance circuits to keep total ~128
if [[ "$MODE" != "single" ]] && [[ -z "${MAX_PENDING_CIRCUITS:-}" ]]; then
    # Auto-calculate: target ~128 total concurrent circuits across all instances
    MAX_PENDING_CIRCUITS=$((128 / INSTANCE_COUNT))
    # Minimum 16 to maintain some parallelism
    [[ $MAX_PENDING_CIRCUITS -lt 16 ]] && MAX_PENDING_CIRCUITS=16
    export MAX_PENDING_CIRCUITS
fi

# Export settings for the Python modules (read from environment)
[[ -n "${MAX_PENDING_CIRCUITS:-}" ]] && export MAX_PENDING_CIRCUITS
[[ -n "${RELIABLE_FIRST_HOP:-}" ]] && export RELIABLE_FIRST_HOP
[[ -n "${DNS_WILDCARD_DOMAIN:-}" ]] && export DNS_WILDCARD_DOMAIN
[[ -n "${DNS_EXPECTED_IP:-}" ]] && export DNS_EXPECTED_IP
[[ -n "${DNS_QUERY_TIMEOUT:-}" ]] && export DNS_QUERY_TIMEOUT
[[ -n "${DNS_MAX_RETRIES:-}" ]] && export DNS_MAX_RETRIES
[[ -n "${DNS_HARD_TIMEOUT:-}" ]] && export DNS_HARD_TIMEOUT
[[ -n "${DNS_RETRY_DELAY:-}" ]] && export DNS_RETRY_DELAY
FIRST_HOP="${FIRST_HOP:-}"
# Export first hop for tracking in dnshealth module results
[[ -n "${FIRST_HOP}" ]] && export EXITMAP_FIRST_HOP="$FIRST_HOP"
ALL_EXITS="${ALL_EXITS:-true}"
DO_ENABLED="${DO_ENABLED:-false}"
R2_ENABLED="${R2_ENABLED:-false}"

# Tor bootstrap retry settings
TOR_BOOTSTRAP_TIMEOUT="${TOR_BOOTSTRAP_TIMEOUT:-90}"
TOR_MAX_BOOTSTRAP_RETRIES="${TOR_MAX_BOOTSTRAP_RETRIES:-3}"
TOR_PROGRESS_CHECK_INTERVAL="${TOR_PROGRESS_CHECK_INTERVAL:-10}"

# Timing constants
INSTANCE_STAGGER_DELAY=5
RETRY_WAIT_SECONDS=10
SCAN_STALL_TIMEOUT=120

# Persistent cache for Tor consensus/descriptors (survives exitmap cleanup)
TOR_CACHE_DIR="$TMP_DIR/tor_cache"

# Validate exitmap installation
EXITMAP_BIN="$EXITMAP_DIR/bin/exitmap"
if [[ ! -f "$EXITMAP_BIN" ]]; then
    echo "ERROR: exitmap not found at: $EXITMAP_BIN" >&2
    echo "" >&2
    echo "Expected directory structure:" >&2
    echo "  EXITMAP_DIR/bin/exitmap" >&2
    echo "" >&2
    echo "Current EXITMAP_DIR: $EXITMAP_DIR" >&2
    echo "" >&2
    echo "To fix, either:" >&2
    echo "  1. Set EXITMAP_DIR in config.env to point to the exitmap installation" >&2
    echo "  2. Move exitmap-dns-health-deploy inside the exitmap directory" >&2
    exit 1
fi

TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
LOCK_FILE="/tmp/exitmap_dns_health.lock"
# Single unified log file for both script and exitmap output
UNIFIED_LOG="$LOG_DIR/validation_${TIMESTAMP}.log"

# Logging helper - writes to unified log
log() { 
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$UNIFIED_LOG"
}

# Helper: Count result files in directory
count_results() {
    find "$1" -name "dnshealth_*.json" 2>/dev/null | wc -l
}

# Helper: Activate virtual environment
activate_venv() {
    cd "$EXITMAP_DIR"
    if [[ -d ".venv" ]]; then
        source .venv/bin/activate
    elif [[ -d "venv" ]]; then
        source venv/bin/activate
    fi
}

# Helper: Read JSON report summary (returns formatted lines)
read_report_summary() {
    local report_file=$1
    python3 -c "
import json, sys
try:
    with open('$report_file') as f:
        m = json.load(f)['metadata']
        # Relay counts
        consensus = m.get('consensus_relays', m.get('total_relays', 0))
        tested = m.get('tested_relays', m.get('total_relays', 0))
        unreachable = m.get('relay_unreachable', 0)
        print(f\"Consensus relays: {consensus}\")
        print(f\"Tested (reachable): {tested} ({m.get('reachability_success_rate_percent', 100):.2f}%)\")
        if unreachable > 0:
            print(f\"Relay Unreachable: {unreachable}\")
        # DNS results
        dns_rate = m.get('dns_success_rate_percent', m.get('success_rate_percent', 0))
        print(f\"Success: {m['success']} ({dns_rate}%)\")
        print(f\"DNS Fail: {m['dns_fail']}\")
        print(f\"Timeout: {m['timeout']}\")
        print(f\"Wrong IP: {m['wrong_ip']}\")
        print(f\"SOCKS Error: {m.get('socks_error', 0)}\")
        print(f\"Network Error: {m.get('network_error', 0)}\")
        cv = m.get('cross_validation', {})
        if cv.get('enabled'):
            print(f\"Cross-validation instances: {cv.get('instances', 'N/A')}\")
            print(f\"Relays recovered by CV: {cv.get('relays_improved', 'N/A')}\")
except Exception as e:
    print(f'Could not read results: {e}')
" 2>&1
}

# Atomic lock to prevent concurrent runs
acquire_lock() {
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
        log "Another instance is already running. Exiting."
        exit 0
    fi
    echo $$ >&9
}

# Cleanup functions
cleanup_instance() {
    local tor_dir=$1
    pkill -9 -f "tor -f.*$tor_dir" 2>/dev/null || true
    
    # Preserve cached-* files for faster Tor bootstrap (valid ~3 hours)
    # Delete everything else (lock, keys, state, auth cookies)
    if [[ -d "$tor_dir" ]]; then
        find "$tor_dir" -mindepth 1 -maxdepth 1 \
            ! -name 'cached-consensus' \
            ! -name 'cached-descriptors' \
            ! -name 'cached-descriptors.new' \
            ! -name 'cached-certs' \
            -exec rm -rf {} \; 2>/dev/null || true
    fi
}

cleanup_all() {
    log "Cleaning up..."
    
    # Kill all child processes of this script first (catches subshells and their children)
    pkill -9 -P $$ 2>/dev/null || true
    
    # Kill all exitmap processes (including orphaned ones from this run)
    # Use multiple patterns to ensure we catch everything
    pkill -9 -f "exitmap dnshealth" 2>/dev/null || true
    pkill -9 -f "bin/exitmap" 2>/dev/null || true
    
    # Kill tor processes started by exitmap
    pkill -9 -f "tor -f.*exitmap_tor" 2>/dev/null || true
    pkill -9 -f "tor -f - __OwningControllerProcess" 2>/dev/null || true
    
    # Wait briefly then kill any stragglers
    sleep 1
    pkill -9 -f "exitmap" 2>/dev/null || true
    pkill -9 -f "tor -f" 2>/dev/null || true
    
    # Clean up all possible tor directories (preserve cached-* for faster next bootstrap)
    for i in $(seq 1 10); do
        cleanup_instance "$TMP_DIR/exitmap_tor_$i"
    done
    cleanup_instance "$TMP_DIR/exitmap_tor"
    rm -f "$LOCK_FILE" 2>/dev/null || true
    rm -f /tmp/exitmap_fps_*.txt 2>/dev/null || true
}

# Helper: Save cached Tor files to persistent storage
save_tor_cache() {
    local tor_dir=$1
    [[ -d "$tor_dir" ]] || return 0
    mkdir -p "$TOR_CACHE_DIR"
    # Copy non-empty cached files (glob is faster than find for few files)
    for f in "$tor_dir"/cached-*; do
        [[ -s "$f" ]] && cp -p "$f" "$TOR_CACHE_DIR/"
    done 2>/dev/null || true
}

# Helper: Restore cached Tor files from persistent storage
restore_tor_cache() {
    local tor_dir=$1
    [[ -d "$TOR_CACHE_DIR" ]] || return 0
    mkdir -p "$tor_dir"
    cp -p "$TOR_CACHE_DIR"/cached-* "$tor_dir/" 2>/dev/null || true
}

# Helper: Prepare tor directory (cleanup + create + restore cache)
prepare_tor_dir() {
    local tor_dir=$1
    cleanup_instance "$tor_dir"
    mkdir -p "$tor_dir"
    chmod 700 "$tor_dir"
    restore_tor_cache "$tor_dir"
}

# Wait for bootstrap completion
wait_for_bootstrap() {
    local log_file=$1
    local instance_name=$2
    local tor_dir="${3:-}"  # Optional tor_dir for cache saving
    local start_time=$(date +%s)
    
    while true; do
        sleep "$TOR_PROGRESS_CHECK_INTERVAL"
        local now=$(date +%s)
        local elapsed=$((now - start_time))
        
        # Single grep pass to check status and get bootstrap percentage
        local log_status=""
        [[ -f "$log_file" ]] && log_status=$(grep -E '(Successfully started Tor|Couldn.t launch Tor|Bootstrapped [0-9]+)' "$log_file" 2>/dev/null | tail -5)
        
        # Check for successful bootstrap (bash pattern match - no subprocess)
        if [[ "$log_status" == *"Successfully started Tor"* ]]; then
            log "$instance_name: Bootstrap complete (${elapsed}s)"
            # Save cache immediately after bootstrap
            [[ -n "$tor_dir" ]] && save_tor_cache "$tor_dir"
            return 0
        fi
        
        # Check for bootstrap failure
        if [[ "$log_status" == *"Couldn't launch Tor"* ]]; then
            log "$instance_name: Bootstrap failed"
            return 1
        fi
        
        # Check for timeout
        if [ $elapsed -gt "$TOR_BOOTSTRAP_TIMEOUT" ]; then
            log "$instance_name: Bootstrap timeout after ${elapsed}s"
            return 1
        fi
        
        # Show progress (extract last bootstrap percentage)
        local boot_pct=$(echo "$log_status" | grep -oP 'Bootstrapped \K\d+' | tail -1)
        log "$instance_name: Bootstrapping ${boot_pct:-0}% (${elapsed}s)"
    done
}

# Wait for scan completion
wait_for_scan() {
    local log_file=$1
    local analysis_dir=$2
    local instance_name=$3
    local start_time=$(date +%s)
    local last_count=0
    local stall_time=0
    
    while true; do
        sleep "$TOR_PROGRESS_CHECK_INTERVAL"
        
        # Check if process is still running
        if ! pgrep -f "analysis-dir $analysis_dir" > /dev/null 2>&1; then
            local count=$(count_results "$analysis_dir")
            log "$instance_name: Scan finished with $count results"
            return 0
        fi
        
        local now=$(date +%s)
        local elapsed=$((now - start_time))
        local count=$(count_results "$analysis_dir")
        
        # Extract progress info from exitmap log
        local probes_sent=""
        local results_breakdown=""
        if [[ -f "$log_file" ]]; then
            # Single awk pass: extract progress info AND count results
            read probed total pct total_ok total_timeout total_failed <<< $(awk '
                /Probed [0-9]+ out of [0-9]+ exit relays.*% done/ {
                    # Extract: "Probed 123 out of 456 exit relays, so we are 27.00% done."
                    for (i=1; i<=NF; i++) {
                        if ($i == "Probed") probed = $(i+1)
                        if ($i == "of") total = $(i+1)
                        if ($i ~ /^[0-9]+\.[0-9]+%$/) pct = substr($i, 1, length($i)-1)
                    }
                }
                /(correct)/ { ok++ }
                /\[timeout\]/ { to++ }
                /\[FAILED\]/ { fail++ }
                END { print probed+0, total+0, pct+0, ok+0, to+0, fail+0 }
            ' "$log_file" 2>/dev/null)
            
            if [[ "$probed" -gt 0 ]] && [[ "$total" -gt 0 ]]; then
                probes_sent="${probed}/${total} (${pct}%) probes sent"
                results_breakdown="${total_ok}ok/${total_timeout}to/${total_failed}fail"
                results_pct=$(awk "BEGIN {printf \"%.2f\", $count * 100 / $total}")
            fi
        fi
        
        # Check for stall (no new results after getting some)
        if [ "$count" -eq "$last_count" ] && [ "$count" -gt 0 ]; then
            stall_time=$((stall_time + TOR_PROGRESS_CHECK_INTERVAL))
            if [ $stall_time -ge "$SCAN_STALL_TIMEOUT" ]; then
                log "$instance_name: Scan appears stalled, considering complete"
                return 0
            fi
            # Show stall warning with time remaining
            local stall_remain=$((SCAN_STALL_TIMEOUT - stall_time))
            # Order: probes sent | results | stalled | breakdown
            if [[ -n "$probes_sent" ]]; then
                log "$instance_name: Scanning... | $probes_sent | $count/$total (${results_pct}%) probes received (${elapsed}s) [stalled ${stall_time}s, ${stall_remain}s to timeout] | $results_breakdown"
            else
                log "$instance_name: Scanning... $count probes received (${elapsed}s) [stalled ${stall_time}s, ${stall_remain}s to timeout]"
            fi
        else
            stall_time=0
            # Order: probes sent | results | breakdown
            if [[ -n "$probes_sent" ]]; then
                log "$instance_name: Scanning... | $probes_sent | $count/$total (${results_pct}%) probes received (${elapsed}s) | $results_breakdown"
            else
                log "$instance_name: Scanning... $count probes received (${elapsed}s)"
            fi
        fi
        last_count=$count
    done
}

# Run a single exitmap instance with retry
# Arguments: instance_name tor_dir analysis_dir log_file [exit_file]
run_instance() {
    local instance_name=$1
    local tor_dir=$2
    local analysis_dir=$3
    local log_file=$4
    local exit_file="${5:-}"
    
    mkdir -p "$analysis_dir"
    activate_venv
    
    # Build command (use absolute path to exitmap)
    local cmd="python3 $EXITMAP_BIN dnshealth"
    cmd="$cmd -t $tor_dir"
    cmd="$cmd --build-delay ${BUILD_DELAY}"
    cmd="$cmd --delay-noise ${DELAY_NOISE}"
    cmd="$cmd --analysis-dir $analysis_dir"
    
    if [[ -n "${FIRST_HOP:-}" ]]; then
        cmd="$cmd --first-hop $FIRST_HOP"
    fi
    
    # Use exit file if provided (for split mode)
    if [[ -n "$exit_file" ]] && [[ -f "$exit_file" ]]; then
        cmd="$cmd --exit-file $exit_file"
    elif [[ "${ALL_EXITS:-true}" == "true" ]]; then
        cmd="$cmd --all-exits"
    fi
    
    # Retry loop
    for attempt in $(seq 1 "$TOR_MAX_BOOTSTRAP_RETRIES"); do
        log "$instance_name: Attempt $attempt/$TOR_MAX_BOOTSTRAP_RETRIES"
        
        # Prepare tor directory (cleanup + create + restore cache)
        prepare_tor_dir "$tor_dir"
        
        # Start exitmap (append to log file so script messages aren't overwritten)
        # PYTHONUNBUFFERED=1 forces immediate output so progress lines are visible in real-time
        PYTHONUNBUFFERED=1 $cmd >> "$log_file" 2>&1 &
        local pid=$!
        
        # Wait for bootstrap
        if wait_for_bootstrap "$log_file" "$instance_name" "$tor_dir"; then
            # Bootstrap succeeded, wait for scan
            wait_for_scan "$log_file" "$analysis_dir" "$instance_name"
            # Kill the process after scan completes or stalls (it may still be running)
            kill -9 "$pid" 2>/dev/null || true
            wait $pid 2>/dev/null || true
            
            local count=$(count_results "$analysis_dir")
            if [ "$count" -gt 0 ]; then
                log "$instance_name: Success with $count results"
                return 0
            else
                log "$instance_name: Completed but no results"
            fi
        fi
        
        # Kill and retry
        kill -9 "$pid" 2>/dev/null || true
        cleanup_instance "$tor_dir"
        
        if [ $attempt -lt "$TOR_MAX_BOOTSTRAP_RETRIES" ]; then
            log "$instance_name: Waiting ${RETRY_WAIT_SECONDS}s before retry..."
            sleep "$RETRY_WAIT_SECONDS"
        fi
    done
    
    log "$instance_name: Failed after $TOR_MAX_BOOTSTRAP_RETRIES attempts"
    return 1
}

# Helper: Merge analysis directories into one
# Args: merged_dir, analysis_dirs...
merge_analysis_dirs() {
    local merged_dir=$1
    shift
    local analysis_dirs=("$@")
    
    mkdir -p "$merged_dir"
    for dir in "${analysis_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            # Use cp -t with + terminator for efficiency (batch copy)
            find "$dir" -name "dnshealth_*.json" -exec cp -t "$merged_dir" {} + 2>/dev/null || true
        fi
    done
}

# Unified aggregation function
# Args: output_dir [--cross-validate] analysis_dirs...
aggregate_results() {
    local output_dir=$1
    shift
    
    local cross_validate=false
    if [[ "${1:-}" == "--cross-validate" ]]; then
        cross_validate=true
        shift
    fi
    
    local analysis_dirs=("$@")
    local report_file="${output_dir}/dns_health_${TIMESTAMP}.json"
    local latest_report="${output_dir}/latest.json"
    local merged_dir="${TMP_DIR}/analysis_${TIMESTAMP}"
    
    # Merge all analysis directories
    merge_analysis_dirs "$merged_dir" "${analysis_dirs[@]}"
    
    local result_count=$(count_results "$merged_dir")
    if $cross_validate; then
        log "Total unique relays: $result_count"
    else
        log "Total results to aggregate: $result_count"
    fi
    
    if [[ "$result_count" -eq 0 ]]; then
        log "No results to aggregate"
        return 1
    fi
    
    # Build aggregation command
    log "Aggregating $($cross_validate && echo "with cross-validation" || echo "results")..."
    local aggregate_cmd="python3 $DEPLOY_DIR/scripts/aggregate_results.py"
    aggregate_cmd="$aggregate_cmd --input $merged_dir"
    aggregate_cmd="$aggregate_cmd --output $report_file"
    
    if $cross_validate; then
        aggregate_cmd="$aggregate_cmd --cross-validate"
        for dir in "${analysis_dirs[@]}"; do
            [[ -d "$dir" ]] && aggregate_cmd="$aggregate_cmd --source $dir"
        done
    fi
    
    [[ -f "$latest_report" ]] && aggregate_cmd="$aggregate_cmd --previous $latest_report"
    
    if $aggregate_cmd --quiet; then
        log "Aggregation complete"
        finalize_report "$output_dir" "$report_file" "$latest_report"
        return 0
    else
        log "Aggregation failed"
        return 1
    fi
}

# Finalize report and display summary
finalize_report() {
    local output_dir=$1
    local report_file=$2
    local latest_report=$3
    
    cp "$report_file" "$latest_report"
    
    # Update files.json manifest
    find "$output_dir" -maxdepth 1 -name "dns_health_*.json" -printf '%f\n' 2>/dev/null \
        | sort -r \
        | head -100 \
        | python3 -c "import sys, json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" \
        > "$output_dir/files.json"
    
    # Display summary
    echo ""
    echo "Summary:"
    read_report_summary "$report_file" | head -8 | sed 's/^/  /'
    echo ""
}

# Cloud uploads
do_uploads() {
    local report_file="${OUTPUT_DIR}/dns_health_${TIMESTAMP}.json"
    local latest_report="${OUTPUT_DIR}/latest.json"
    
    local pids=()
    
    if [[ "${DO_ENABLED:-false}" == "true" ]] && [[ -x "$DEPLOY_DIR/scripts/upload-do.sh" ]]; then
        log "Uploading to DigitalOcean Spaces..."
        "$DEPLOY_DIR/scripts/upload-do.sh" &
        pids+=($!)
    fi
    
    if [[ "${R2_ENABLED:-false}" == "true" ]] && [[ -x "$DEPLOY_DIR/scripts/upload-r2.sh" ]]; then
        log "Uploading to Cloudflare R2..."
        "$DEPLOY_DIR/scripts/upload-r2.sh" &
        pids+=($!)
    fi
    
    for pid in "${pids[@]:-}"; do
        if ! wait "$pid"; then
            log "Upload failed (PID $pid)"
        fi
    done
}

# Helper: Start N parallel instances
# Sets global arrays: INSTANCE_PIDS, INSTANCE_ANALYSIS_DIRS, INSTANCE_LOGS
# Args: mode_prefix instance_count [use_exit_files]
start_parallel_instances() {
    local mode_prefix=$1
    local n=$2
    local use_exit_files=${3:-false}
    
    INSTANCE_PIDS=()
    INSTANCE_ANALYSIS_DIRS=()
    INSTANCE_LOGS=()
    
    for i in $(seq 1 $n); do
        local tor_dir="$TMP_DIR/exitmap_tor_$i"
        local analysis_dir="${TMP_DIR}/analysis_${TIMESTAMP}_${mode_prefix}$i"
        # Temp log for progress tracking (merged into unified log after completion)
        local log_file="$TMP_DIR/exitmap_${mode_prefix}$i.log"
        
        INSTANCE_ANALYSIS_DIRS+=("$analysis_dir")
        INSTANCE_LOGS+=("$log_file")
        
        if $use_exit_files; then
            local exit_file="${FPS_BASE}.$i"
            (run_instance "${mode_prefix}Instance$i" "$tor_dir" "$analysis_dir" "$log_file" "$exit_file") &
        else
            (run_instance "${mode_prefix}Instance$i" "$tor_dir" "$analysis_dir" "$log_file") &
        fi
        INSTANCE_PIDS+=($!)
        
        # Stagger starts to avoid thundering herd
        [[ $i -lt $n ]] && sleep "$INSTANCE_STAGGER_DELAY"
    done
    
    log "Started $n ${mode_prefix} instances (PIDs: ${INSTANCE_PIDS[*]})"
}

# Helper: Wait for all parallel instances to complete
# Returns 0 if any succeeded, 1 if all failed
# Also merges instance logs into unified log
wait_parallel_instances() {
    local mode_prefix=$1
    local any_success=false
    
    for i in "${!INSTANCE_PIDS[@]}"; do
        local exit_code=0
        wait "${INSTANCE_PIDS[$i]}" || exit_code=$?
        log "${mode_prefix}Instance$((i+1)) exit: $exit_code"
        [[ $exit_code -eq 0 ]] && any_success=true
    done
    
    # Merge instance logs into unified log and clean up
    for log_file in "${INSTANCE_LOGS[@]}"; do
        if [[ -f "$log_file" ]]; then
            cat "$log_file" >> "$UNIFIED_LOG"
            rm -f "$log_file"
        fi
    done
    
    $any_success
}

# Mode: Single instance
run_single() {
    local tor_dir="$TMP_DIR/exitmap_tor"
    local analysis_dir="${TMP_DIR}/analysis_${TIMESTAMP}"
    # Use unified log directly for single instance mode
    local log_file="$UNIFIED_LOG"
    
    log "=== Single Instance Mode ==="
    
    if run_instance "Instance" "$tor_dir" "$analysis_dir" "$log_file"; then
        aggregate_results "$OUTPUT_DIR" "$analysis_dir"
        do_uploads
        return 0
    else
        return 1
    fi
}

# Mode: Cross-validation (N instances scan ALL relays)
run_cross_validate() {
    local n=$INSTANCE_COUNT
    log "=== Cross-Validation Mode ($n instances) ==="
    log "Each instance scans ALL relays. Relay passes if ANY instance succeeds."
    
    start_parallel_instances "cv" "$n" false
    local any_success=false
    wait_parallel_instances "CV-" && any_success=true
    
    aggregate_results "$OUTPUT_DIR" --cross-validate "${INSTANCE_ANALYSIS_DIRS[@]}"
    do_uploads
    
    $any_success
}

# Mode: Split (divide relays among N instances)
run_split() {
    local n=$INSTANCE_COUNT
    log "=== Split Mode ($n instances) ==="
    log "Dividing relays among $n instances for parallel scanning."
    
    # First, bootstrap a temporary Tor to get the relay list
    log "Bootstrapping Tor to get relay list..."
    local temp_tor_dir="$TMP_DIR/exitmap_tor_temp"
    local temp_log="$TMP_DIR/bootstrap_temp.log"
    
    prepare_tor_dir "$temp_tor_dir"
    activate_venv
    
    # Quick bootstrap to get consensus
    python3 -c "
import stem.process
import os
import sys

tor_dir = '$temp_tor_dir'
os.makedirs(tor_dir, exist_ok=True)

try:
    tor_process = stem.process.launch_tor_with_config(
        config={
            'DataDirectory': tor_dir,
            'ControlPort': 'auto',
            'SocksPort': 'auto',
        },
        init_msg_handler=lambda line: print(line) if 'Bootstrapped' in line else None,
        timeout=120,
        take_ownership=True,
    )
    print('Tor bootstrapped successfully')
    tor_process.kill()
except Exception as e:
    print(f'Bootstrap failed: {e}', file=sys.stderr)
    sys.exit(1)
" > "$temp_log" 2>&1
    
    if [ $? -ne 0 ]; then
        log "Failed to bootstrap Tor for relay list"
        cat "$temp_log"
        return 1
    fi
    
    # Extract and split fingerprints (set global FPS_BASE for helper)
    FPS_BASE="/tmp/exitmap_fps_${TIMESTAMP}"
    log "Extracting and splitting relay fingerprints..."
    python3 "$DEPLOY_DIR/scripts/get_exit_fingerprints.py" \
        "$temp_tor_dir" \
        --output "$FPS_BASE" \
        --split "$n" \
        $([[ "${ALL_EXITS:-true}" == "true" ]] && echo "--all-exits" || echo "")
    
    cleanup_instance "$temp_tor_dir"
    
    # Verify split files exist
    for i in $(seq 1 $n); do
        if [[ ! -f "${FPS_BASE}.$i" ]]; then
            log "Split file ${FPS_BASE}.$i not found"
            return 1
        fi
        local count=$(wc -l < "${FPS_BASE}.$i")
        log "Split $i: $count relays"
    done
    
    # Start instances with exit files
    start_parallel_instances "split" "$n" true
    local any_success=false
    wait_parallel_instances "Split-" && any_success=true
    
    # Clean up split files
    rm -f ${FPS_BASE}.* 2>/dev/null || true
    
    aggregate_results "$OUTPUT_DIR" "${INSTANCE_ANALYSIS_DIRS[@]}"
    do_uploads
    
    $any_success
}

# Main entry point
main() {
    mkdir -p "$OUTPUT_DIR" "$LOG_DIR" "$TMP_DIR"
    
    acquire_lock
    # Trap EXIT and common signals to ensure cleanup on any termination
    trap cleanup_all EXIT INT TERM HUP
    
    # Log system and configuration info for debugging
    log "=============================================="
    log "DNS Health Validation"
    log "=============================================="
    log "Started: $(date -Iseconds)"
    log "Hostname: $(hostname)"
    log "Mode: $MODE"
    if [[ "$MODE" != "single" ]]; then
        log "Instances: $INSTANCE_COUNT"
    fi
    log ""
    log "=== Configuration ==="
    log "EXITMAP_DIR: $EXITMAP_DIR"
    log "OUTPUT_DIR: $OUTPUT_DIR"
    log "BUILD_DELAY: $BUILD_DELAY"
    log "DELAY_NOISE: $DELAY_NOISE"
    log "ALL_EXITS: ${ALL_EXITS:-true}"
    log "FIRST_HOP: ${FIRST_HOP:-<random>}"
    log "RELIABLE_FIRST_HOP: ${RELIABLE_FIRST_HOP:-false}"
    log "TOR_BOOTSTRAP_TIMEOUT: ${TOR_BOOTSTRAP_TIMEOUT}s"
    log "TOR_MAX_BOOTSTRAP_RETRIES: $TOR_MAX_BOOTSTRAP_RETRIES"
    log "TOR_PROGRESS_CHECK_INTERVAL: ${TOR_PROGRESS_CHECK_INTERVAL}s"
    if [[ "$MODE" != "single" ]] && [[ "${MAX_PENDING_CIRCUITS:-128}" -lt 128 ]]; then
        log "MAX_PENDING_CIRCUITS: ${MAX_PENDING_CIRCUITS} (auto-scaled for $INSTANCE_COUNT instances)"
    else
        log "MAX_PENDING_CIRCUITS: ${MAX_PENDING_CIRCUITS:-128}"
    fi
    log "DNS_WILDCARD_DOMAIN: ${DNS_WILDCARD_DOMAIN:-tor.exit.validator.1aeo.com}"
    log "DNS_EXPECTED_IP: ${DNS_EXPECTED_IP:-64.65.4.1}"
    log "DNS_QUERY_TIMEOUT: ${DNS_QUERY_TIMEOUT:-45}s"
    
    # Log git version if available (single git command)
    if command -v git &>/dev/null && [[ -d "$EXITMAP_DIR/.git" ]]; then
        local git_info=$(cd "$EXITMAP_DIR" && git log -1 --format="%D|%h" 2>/dev/null)
        local git_dirty=$(cd "$EXITMAP_DIR" && git diff --quiet 2>/dev/null && echo "" || echo " (dirty)")
        local git_branch=${git_info%%,*}  # First ref (usually HEAD -> branch)
        git_branch=${git_branch#HEAD -> }  # Remove "HEAD -> " prefix
        local git_hash=${git_info#*|}
        log "Git: ${git_branch:-detached} @ ${git_hash:-unknown}$git_dirty"
    fi
    log "=============================================="
    
    local start_time=$(date +%s)
    local exit_code=0
    
    case "$MODE" in
        single)
            run_single || exit_code=$?
            ;;
        cross-validate)
            run_cross_validate || exit_code=$?
            ;;
        split)
            run_split || exit_code=$?
            ;;
        *)
            log "Unknown mode: $MODE"
            exit 1
            ;;
    esac
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Cleanup old analysis directories (keep last 3)
    if [[ "${CLEANUP_OLD:-true}" == "true" ]]; then
        local keep_count="${ANALYSIS_KEEP_COUNT:-3}"
        local dirs_to_remove=$(ls -dt "$TMP_DIR"/analysis_* 2>/dev/null | tail -n +$((keep_count + 1)))
        if [[ -n "$dirs_to_remove" ]]; then
            echo "$dirs_to_remove" | xargs rm -rf 2>/dev/null || true
            log "Cleaned up old analysis directories (keeping last $keep_count)"
        fi
    fi
    
    log "=============================================="
    log "=== Run Complete ==="
    log "=============================================="
    log "Duration: ${duration}s ($((duration / 60))m $((duration % 60))s)"
    log "Exit code: $exit_code"
    log "Ended: $(date -Iseconds)"
    
    # Log final statistics only if this run produced a new report
    local this_run_report="${OUTPUT_DIR}/dns_health_${TIMESTAMP}.json"
    if [[ -f "$this_run_report" ]]; then
        log ""
        log "=== Final Results ==="
        read_report_summary "$this_run_report" | while read line; do log "$line"; done
        log ""
        log "Report: $this_run_report"
        log "Latest: $OUTPUT_DIR/latest.json"
    elif [[ $exit_code -ne 0 ]]; then
        log ""
        log "=== No Results ==="
        log "Run failed without producing results."
    fi
    
    log "=============================================="
    
    # Unified log is kept at: $UNIFIED_LOG
    
    exit $exit_code
}

main "$@"
