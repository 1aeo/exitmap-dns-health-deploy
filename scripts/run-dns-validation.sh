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

# Validate command-line arguments
validate_args() {
    # Validate INSTANCE_COUNT is positive integer between 1-16
    if [[ "$MODE" != "single" ]]; then
        if ! [[ "$INSTANCE_COUNT" =~ ^[0-9]+$ ]]; then
            echo "Error: Instance count must be a number, got: $INSTANCE_COUNT" >&2
            exit 1
        fi
        if [[ "$INSTANCE_COUNT" -lt 1 ]] || [[ "$INSTANCE_COUNT" -gt 16 ]]; then
            echo "Error: Instance count must be 1-16, got: $INSTANCE_COUNT" >&2
            exit 1
        fi
    fi
}
validate_args

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
LOCK_FILE="${TMP_DIR}/exitmap_dns_health.lock"
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
# Grace period for straggling probes before termination
export EXITMAP_GRACE_TIMEOUT="${EXITMAP_GRACE_TIMEOUT:-10}"
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
        scan = m.get('scan', {})
        # Relay counts (new field names)
        consensus = m.get('consensus_relays', 0)
        tested = m.get('tested_relays', 0)
        unreachable = m.get('unreachable_relays', 0)
        print(f\"Consensus relays: {consensus}\")
        print(f\"Tested (reachable): {tested} ({m.get('reachability_rate_percent', 100):.2f}%)\")
        if unreachable > 0:
            print(f\"Unreachable Relays: {unreachable}\")
        # DNS results (new dns_ prefixed field names)
        dns_rate = m.get('dns_success_rate_percent', 0)
        print(f\"DNS Success: {m.get('dns_success', 0)} ({dns_rate}%)\")
        print(f\"DNS Fail: {m.get('dns_fail', 0)}\")
        print(f\"DNS Timeout: {m.get('dns_timeout', 0)}\")
        print(f\"DNS Wrong IP: {m.get('dns_wrong_ip', 0)}\")
        print(f\"DNS SOCKS Error: {m.get('dns_socks_error', 0)}\")
        print(f\"DNS Network Error: {m.get('dns_network_error', 0)}\")
        # Scan mode info
        scan_type = scan.get('type', 'single')
        if scan_type == 'cross_validate':
            cv = m.get('cross_validation', {})
            print(f\"Scan Mode: Cross-validation ({scan.get('instances', 0)} instances)\")
            print(f\"Relays recovered by CV: {cv.get('relays_improved', 'N/A')}\")
        elif scan_type == 'split':
            print(f\"Scan Mode: Split ({scan.get('instances', 0)} instances)\")
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

# === Process Management ===
# Global array to track managed process IDs (safer than pkill patterns)
declare -a MANAGED_PIDS=()
declare -a MANAGED_TOR_DIRS=()

# Register a PID for cleanup tracking
register_pid() {
    MANAGED_PIDS+=("$1")
}

# Kill a process and its children by PID (safer than pattern matching)
kill_process_tree() {
    local pid=$1
    [[ -z "$pid" ]] && return
    
    # Check if process exists
    kill -0 "$pid" 2>/dev/null || return 0
    
    # Get process group ID and kill the group
    local pgid
    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ') || true
    
    if [[ -n "$pgid" ]] && [[ "$pgid" != "0" ]]; then
        # Kill process group (negative PID)
        kill -TERM -"$pgid" 2>/dev/null || true
        sleep 0.5
        kill -9 -"$pgid" 2>/dev/null || true
    else
        # Fallback: kill individual process
        kill -TERM "$pid" 2>/dev/null || true
        sleep 0.5
        kill -9 "$pid" 2>/dev/null || true
    fi
}

# Cleanup a single tor directory (without pkill pattern matching)
cleanup_instance() {
    local tor_dir=$1
    
    # Find and kill tor process by its PID file if it exists
    local tor_pid_file="$tor_dir/tor.pid"
    if [[ -f "$tor_pid_file" ]]; then
        local tor_pid
        tor_pid=$(cat "$tor_pid_file" 2>/dev/null) || true
        [[ -n "$tor_pid" ]] && kill_process_tree "$tor_pid"
    fi
    
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
    
    # 1. Kill all tracked/managed PIDs first (safe - we started these)
    for pid in "${MANAGED_PIDS[@]:-}"; do
        kill_process_tree "$pid"
    done
    MANAGED_PIDS=()
    
    # 2. Kill all direct child processes of this script (safe - only our children)
    # This catches any background processes we spawned
    local children
    children=$(pgrep -P $$ 2>/dev/null) || true
    for child_pid in $children; do
        kill_process_tree "$child_pid"
    done
    
    # 3. Clean up tracked tor directories
    for tor_dir in "${MANAGED_TOR_DIRS[@]:-}"; do
        cleanup_instance "$tor_dir"
    done
    MANAGED_TOR_DIRS=()
    
    # 4. Clean up any remaining tor directories from known paths
    for i in $(seq 1 16); do
        cleanup_instance "$TMP_DIR/exitmap_tor_$i"
        cleanup_instance "$TMP_DIR/exitmap_tor_w${i}_1"
        cleanup_instance "$TMP_DIR/exitmap_tor_w${i}_2"
        cleanup_instance "$TMP_DIR/exitmap_tor_w${i}_3"
        cleanup_instance "$TMP_DIR/exitmap_tor_w${i}_4"
    done
    cleanup_instance "$TMP_DIR/exitmap_tor"
    cleanup_instance "$TMP_DIR/exitmap_tor_temp"
    
    # 5. Cleanup temp files
    rm -f "$LOCK_FILE" 2>/dev/null || true
    rm -f "$TMP_DIR"/exitmap_fps_*.txt 2>/dev/null || true
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
        
        # Extract progress info from exitmap log (using Python for safe parsing)
        local probes_sent=""
        local results_breakdown=""
        local results_pct=""
        if [[ -f "$log_file" ]]; then
            # Use Python helper for safe log parsing (no shell injection risk)
            local progress_json
            progress_json=$(python3 "$DEPLOY_DIR/scripts/parse_exitmap_log.py" "$log_file" 2>/dev/null) || progress_json='{}'
            
            # Extract values from JSON using Python (safer than jq dependency)
            local probed total pct total_ok total_timeout total_failed
            read probed total pct total_ok total_timeout total_failed <<< $(python3 -c "
import json, sys
try:
    d = json.loads('$progress_json')
    print(d.get('probed',0), d.get('total',0), d.get('pct',0), d.get('ok',0), d.get('timeout',0), d.get('failed',0))
except: print('0 0 0 0 0 0')
" 2>/dev/null)
            
            if [[ "$probed" -gt 0 ]] && [[ "$total" -gt 0 ]]; then
                probes_sent="${probed}/${total} (${pct}%) probes sent"
                results_breakdown="${total_ok}ok/${total_timeout}to/${total_failed}fail"
                # Calculate percentage using Python (safe arithmetic)
                results_pct=$(python3 -c "print(f'{$count * 100 / $total:.2f}')" 2>/dev/null || echo "0.00")
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
    
    # Track this tor directory for cleanup
    MANAGED_TOR_DIRS+=("$tor_dir")
    
    # Retry loop
    for attempt in $(seq 1 "$TOR_MAX_BOOTSTRAP_RETRIES"); do
        log "$instance_name: Attempt $attempt/$TOR_MAX_BOOTSTRAP_RETRIES"
        
        # Prepare tor directory (cleanup + create + restore cache)
        prepare_tor_dir "$tor_dir"
        
        # Start exitmap in its own process group for clean termination
        # PYTHONUNBUFFERED=1 forces immediate output so progress lines are visible in real-time
        setsid bash -c "PYTHONUNBUFFERED=1 $cmd" >> "$log_file" 2>&1 &
        local pid=$!
        register_pid "$pid"
        
        # Wait for bootstrap
        if wait_for_bootstrap "$log_file" "$instance_name" "$tor_dir"; then
            # Bootstrap succeeded, wait for scan
            wait_for_scan "$log_file" "$analysis_dir" "$instance_name"
            # Kill the process tree after scan completes or stalls (it may still be running)
            kill_process_tree "$pid"
            wait $pid 2>/dev/null || true
            
            local count=$(count_results "$analysis_dir")
            if [ "$count" -gt 0 ]; then
                log "$instance_name: Success with $count results"
                return 0
            else
                log "$instance_name: Completed but no results"
            fi
        fi
        
        # Kill process tree and retry
        kill_process_tree "$pid"
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
# Args: output_dir [--cross-validate] [--wave-stats FILE] analysis_dirs...
aggregate_results() {
    local output_dir=$1
    shift
    
    local cross_validate=false
    local wave_stats_file=""
    
    # Parse optional flags
    while [[ "${1:-}" == --* ]]; do
        case "$1" in
            --cross-validate)
                cross_validate=true
                shift
                ;;
            --wave-stats)
                wave_stats_file="$2"
                shift 2
                ;;
            *)
                break
                ;;
        esac
    done
    
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
    
    # Pass scan mode info based on MODE
    case "$MODE" in
        single)
            aggregate_cmd="$aggregate_cmd --scan-type single --scan-instances 1"
            ;;
        cross-validate)
            aggregate_cmd="$aggregate_cmd --scan-type cross_validate --scan-instances $INSTANCE_COUNT"
            ;;
        split)
            aggregate_cmd="$aggregate_cmd --scan-type split --scan-instances $INSTANCE_COUNT"
            ;;
    esac
    
    if $cross_validate; then
        aggregate_cmd="$aggregate_cmd --cross-validate"
        for dir in "${analysis_dirs[@]}"; do
            [[ -d "$dir" ]] && aggregate_cmd="$aggregate_cmd --source $dir"
        done
    fi
    
    [[ -f "$latest_report" ]] && aggregate_cmd="$aggregate_cmd --previous $latest_report"
    
    # Add wave stats if provided
    [[ -n "$wave_stats_file" ]] && [[ -f "$wave_stats_file" ]] && aggregate_cmd="$aggregate_cmd --wave-stats $wave_stats_file"
    
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

# =============================================================================
# WAVE-BASED CROSS-VALIDATION
# =============================================================================

# Wave configuration (from config.env)
WAVE_BATCH_SIZE="${WAVE_BATCH_SIZE:-0}"
WAVE_MAX_RETRIES="${WAVE_MAX_RETRIES:-2}"

# Global for tracking wave retry count
WAVE_RETRY_COUNT=0

# Log wave progress with memory and process counts
log_wave_progress() {
    local wave=$1
    local phase=$2  # "start" or "end"
    local mem_used=$(free -m | awk '/^Mem:/ {print $3}')
    local mem_total=$(free -m | awk '/^Mem:/ {print $2}')
    local proc_count=$(pgrep -c -f "exitmap" 2>/dev/null || echo 0)
    log "Wave $wave ($phase): Memory ${mem_used}MB/${mem_total}MB, Processes: $proc_count"
}

# Get all exit fingerprints via temporary Tor bootstrap
# Args: output_file
get_all_fingerprints() {
    local output_file=$1
    
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
        cleanup_instance "$temp_tor_dir"
        return 1
    fi
    
    # Extract fingerprints to single file
    python3 "$DEPLOY_DIR/scripts/get_exit_fingerprints.py" \
        "$temp_tor_dir" \
        --output "$output_file" \
        $([[ "${ALL_EXITS:-true}" == "true" ]] && echo "--all-exits" || echo "")
    
    local result=$?
    cleanup_instance "$temp_tor_dir"
    
    if [[ $result -ne 0 ]] || [[ ! -f "$output_file" ]]; then
        log "Failed to extract fingerprints"
        return 1
    fi
    
    local count=$(wc -l < "$output_file")
    log "Found $count exit relays"
    return 0
}

# Run a single wave (all N instances scan the wave's fingerprints)
# Args: wave_num total_waves wave_file instance_count
# Returns: 0 on success, 1 on failure
run_single_wave() {
    local wave=$1
    local total_waves=$2
    local wave_file=$3
    local n=$4
    
    local wave_relay_count=$(wc -l < "$wave_file")
    log "=== Wave $wave/$total_waves ($wave_relay_count relays) ==="
    log_wave_progress "$wave" "start"
    
    local wave_start=$(date +%s)
    
    # Start N instances for this wave
    WAVE_INSTANCE_PIDS=()
    WAVE_INSTANCE_ANALYSIS_DIRS=()
    WAVE_INSTANCE_LOGS=()
    
    for i in $(seq 1 $n); do
        local tor_dir="$TMP_DIR/exitmap_tor_w${wave}_$i"
        local analysis_dir="${TMP_DIR}/analysis_${TIMESTAMP}_cv${i}_w${wave}"
        local log_file="$TMP_DIR/exitmap_cv${i}_w${wave}.log"
        
        WAVE_INSTANCE_ANALYSIS_DIRS+=("$analysis_dir")
        WAVE_INSTANCE_LOGS+=("$log_file")
        
        # Each instance scans the same wave file (all instances = cross-validation)
        (run_instance "cv${i}_w${wave}" "$tor_dir" "$analysis_dir" "$log_file" "$wave_file") &
        WAVE_INSTANCE_PIDS+=($!)
        
        # Stagger starts
        [[ $i -lt $n ]] && sleep "$INSTANCE_STAGGER_DELAY"
    done
    
    log "Wave $wave: Started $n instances (PIDs: ${WAVE_INSTANCE_PIDS[*]})"
    
    # Wait for all instances in this wave
    local any_success=false
    for i in "${!WAVE_INSTANCE_PIDS[@]}"; do
        local exit_code=0
        wait "${WAVE_INSTANCE_PIDS[$i]}" || exit_code=$?
        [[ $exit_code -eq 0 ]] && any_success=true
    done
    
    # Merge instance logs into unified log
    for log_file in "${WAVE_INSTANCE_LOGS[@]}"; do
        if [[ -f "$log_file" ]]; then
            cat "$log_file" >> "$UNIFIED_LOG"
            rm -f "$log_file"
        fi
    done
    
    local wave_end=$(date +%s)
    local wave_duration=$((wave_end - wave_start))
    
    log_wave_progress "$wave" "end"
    log "Wave $wave completed in ${wave_duration}s"
    
    # Accumulate analysis dirs for final aggregation
    ALL_WAVE_ANALYSIS_DIRS+=("${WAVE_INSTANCE_ANALYSIS_DIRS[@]}")
    
    # Record wave stats
    echo "{\"wave\": $wave, \"relays\": $wave_relay_count, \"duration_sec\": $wave_duration, \"retries\": ${WAVE_RETRY_COUNT:-0}, \"batch_size\": $WAVE_BATCH_SIZE}" >> "$WAVE_STATS_FILE"
    
    $any_success
}

# Run a wave with retry logic
# Args: wave_num total_waves wave_file instance_count
run_wave_with_retry() {
    local wave=$1
    local total_waves=$2
    local wave_file=$3
    local n=$4
    local max_retries=${WAVE_MAX_RETRIES:-2}
    
    WAVE_RETRY_COUNT=0
    
    while true; do
        if run_single_wave "$wave" "$total_waves" "$wave_file" "$n"; then
            return 0
        fi
        
        ((WAVE_RETRY_COUNT++))
        if [[ $WAVE_RETRY_COUNT -ge $max_retries ]]; then
            log "Wave $wave failed after $WAVE_RETRY_COUNT retries"
            return 1
        fi
        
        log "Wave $wave failed, retry $WAVE_RETRY_COUNT/$max_retries in 10s..."
        sleep 10
    done
}

# Wave-based cross-validation mode
# Args: instance_count
run_cross_validate_waves() {
    local n=$1
    
    log "=== Wave-Based Cross-Validation Mode ==="
    log "Instances: $n, Batch size: $WAVE_BATCH_SIZE relays/wave"
    
    # Get all fingerprints
    local fps_all="${TMP_DIR}/exitmap_fps_all_${TIMESTAMP}"
    if ! get_all_fingerprints "$fps_all"; then
        log "Failed to get relay fingerprints"
        return 1
    fi
    
    local total_relays=$(wc -l < "$fps_all")
    local total_waves=$(( (total_relays + WAVE_BATCH_SIZE - 1) / WAVE_BATCH_SIZE ))
    
    log "Processing $total_relays relays in $total_waves waves of $WAVE_BATCH_SIZE"
    
    # Initialize wave stats file
    WAVE_STATS_FILE="$TMP_DIR/wave_stats_${TIMESTAMP}.jsonl"
    > "$WAVE_STATS_FILE"
    
    # Initialize global array for all analysis directories
    ALL_WAVE_ANALYSIS_DIRS=()
    
    local waves_succeeded=0
    local waves_failed=0
    
    # Process each wave
    for wave in $(seq 1 $total_waves); do
        local start_line=$(( (wave - 1) * WAVE_BATCH_SIZE + 1 ))
        local end_line=$(( wave * WAVE_BATCH_SIZE ))
        
        # Extract this wave's fingerprints
        local wave_file="${TMP_DIR}/exitmap_fps_wave${wave}_${TIMESTAMP}"
        sed -n "${start_line},${end_line}p" "$fps_all" > "$wave_file"
        
        if run_wave_with_retry "$wave" "$total_waves" "$wave_file" "$n"; then
            ((waves_succeeded++))
        else
            ((waves_failed++))
        fi
        
        # Clean up wave file
        rm -f "$wave_file"
    done
    
    # Clean up fingerprints file
    rm -f "$fps_all"
    
    log "=== Wave Summary ==="
    log "Waves succeeded: $waves_succeeded/$total_waves"
    [[ $waves_failed -gt 0 ]] && log "Waves failed: $waves_failed"
    
    # Aggregate all results with cross-validation
    if [[ ${#ALL_WAVE_ANALYSIS_DIRS[@]} -gt 0 ]]; then
        aggregate_results "$OUTPUT_DIR" --cross-validate --wave-stats "$WAVE_STATS_FILE" "${ALL_WAVE_ANALYSIS_DIRS[@]}"
        do_uploads
    else
        log "No results to aggregate"
        return 1
    fi
    
    [[ $waves_succeeded -gt 0 ]]
}

# Mode: Cross-validation (N instances scan ALL relays)
run_cross_validate() {
    local n=$INSTANCE_COUNT
    log "=== Cross-Validation Mode ($n instances) ==="
    log "Each instance scans ALL relays. Relay passes if ANY instance succeeds."
    
    # Use wave-based mode if WAVE_BATCH_SIZE > 0
    if [[ "${WAVE_BATCH_SIZE:-0}" -gt 0 ]]; then
        run_cross_validate_waves "$n"
        return $?
    fi
    
    # Original all-at-once mode
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
    FPS_BASE="${TMP_DIR}/exitmap_fps_${TIMESTAMP}"
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
