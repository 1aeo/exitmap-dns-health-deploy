#!/bin/bash
# Test wave-based cross-validation logic
# Run: ./tests/test_wave_validation.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}PASS${NC}: $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}FAIL${NC}: $1"
    echo "  Expected: $2"
    echo "  Got: $3"
}

run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
    "$@"
}

# =============================================================================
# Tests
# =============================================================================

test_wave_calculation() {
    # Test: 3123 relays / 400 batch = 8 waves (ceiling division)
    local total=3123 batch=400
    local expected=8
    local actual=$(( (total + batch - 1) / batch ))
    
    if [[ $actual -eq $expected ]]; then
        pass "Wave calculation: $total relays / $batch batch = $actual waves"
    else
        fail "Wave calculation" "$expected" "$actual"
    fi
}

test_wave_calculation_exact() {
    # Test: 800 relays / 400 batch = 2 waves (exact division)
    local total=800 batch=400
    local expected=2
    local actual=$(( (total + batch - 1) / batch ))
    
    if [[ $actual -eq $expected ]]; then
        pass "Wave calculation (exact): $total relays / $batch batch = $actual waves"
    else
        fail "Wave calculation (exact)" "$expected" "$actual"
    fi
}

test_wave_calculation_small() {
    # Test: 50 relays / 400 batch = 1 wave
    local total=50 batch=400
    local expected=1
    local actual=$(( (total + batch - 1) / batch ))
    
    if [[ $actual -eq $expected ]]; then
        pass "Wave calculation (small): $total relays / $batch batch = $actual waves"
    else
        fail "Wave calculation (small)" "$expected" "$actual"
    fi
}

test_fingerprint_splitting() {
    # Create test fingerprints file
    local test_dir="/tmp/test_wave_$$"
    mkdir -p "$test_dir"
    seq 1 1000 > "$test_dir/fps.txt"
    
    # Split into 400-relay batches using sed
    sed -n "1,400p" "$test_dir/fps.txt" > "$test_dir/wave1.txt"
    sed -n "401,800p" "$test_dir/fps.txt" > "$test_dir/wave2.txt"
    sed -n "801,1000p" "$test_dir/fps.txt" > "$test_dir/wave3.txt"
    
    local wave1_count=$(wc -l < "$test_dir/wave1.txt")
    local wave2_count=$(wc -l < "$test_dir/wave2.txt")
    local wave3_count=$(wc -l < "$test_dir/wave3.txt")
    
    local all_pass=true
    
    if [[ $wave1_count -ne 400 ]]; then
        fail "Fingerprint splitting wave 1" "400" "$wave1_count"
        all_pass=false
    fi
    
    if [[ $wave2_count -ne 400 ]]; then
        fail "Fingerprint splitting wave 2" "400" "$wave2_count"
        all_pass=false
    fi
    
    if [[ $wave3_count -ne 200 ]]; then
        fail "Fingerprint splitting wave 3" "200" "$wave3_count"
        all_pass=false
    fi
    
    if $all_pass; then
        pass "Fingerprint splitting: 1000 fps -> 400, 400, 200"
    fi
    
    # Cleanup
    rm -rf "$test_dir"
}

test_wave_stats_json() {
    # Test wave stats JSON format
    local test_dir="/tmp/test_wave_$$"
    mkdir -p "$test_dir"
    
    # Simulate wave stats output
    local stats_file="$test_dir/wave_stats.jsonl"
    echo '{"wave": 1, "relays": 400, "duration_sec": 180, "retries": 0, "batch_size": 400}' > "$stats_file"
    echo '{"wave": 2, "relays": 400, "duration_sec": 175, "retries": 0, "batch_size": 400}' >> "$stats_file"
    echo '{"wave": 3, "relays": 200, "duration_sec": 90, "retries": 1, "batch_size": 400}' >> "$stats_file"
    
    # Verify JSON is valid and calculate totals
    local total_waves=$(wc -l < "$stats_file")
    local total_retries=$(python3 -c "
import json
with open('$stats_file') as f:
    waves = [json.loads(line) for line in f]
print(sum(w.get('retries', 0) for w in waves))
")
    local total_relays=$(python3 -c "
import json
with open('$stats_file') as f:
    waves = [json.loads(line) for line in f]
print(sum(w.get('relays', 0) for w in waves))
")
    
    local all_pass=true
    
    if [[ $total_waves -ne 3 ]]; then
        fail "Wave stats: total waves" "3" "$total_waves"
        all_pass=false
    fi
    
    if [[ $total_retries -ne 1 ]]; then
        fail "Wave stats: total retries" "1" "$total_retries"
        all_pass=false
    fi
    
    if [[ $total_relays -ne 1000 ]]; then
        fail "Wave stats: total relays" "1000" "$total_relays"
        all_pass=false
    fi
    
    if $all_pass; then
        pass "Wave stats JSON format valid"
    fi
    
    # Cleanup
    rm -rf "$test_dir"
}

test_wave_retry_bounds() {
    # Test WAVE_MAX_RETRIES bounds
    local max_retries=2
    local retry_count=0
    local should_retry=true
    
    # Simulate retry loop
    while $should_retry; do
        retry_count=$((retry_count + 1))
        if [[ $retry_count -ge $max_retries ]]; then
            should_retry=false
        fi
    done
    
    if [[ $retry_count -eq $max_retries ]]; then
        pass "Wave retry bounds: stopped at max_retries=$max_retries"
    else
        fail "Wave retry bounds" "$max_retries" "$retry_count"
    fi
}

test_line_range_extraction() {
    # Test sed line range extraction for waves
    local test_dir="/tmp/test_wave_$$"
    mkdir -p "$test_dir"
    
    # Create test file with known content
    for i in $(seq 1 10); do
        echo "FP_$i"
    done > "$test_dir/fps.txt"
    
    # Extract lines 3-5
    local extracted=$(sed -n "3,5p" "$test_dir/fps.txt" | tr '\n' ',')
    local expected="FP_3,FP_4,FP_5,"
    
    if [[ "$extracted" == "$expected" ]]; then
        pass "Line range extraction: sed -n '3,5p' works correctly"
    else
        fail "Line range extraction" "$expected" "$extracted"
    fi
    
    # Cleanup
    rm -rf "$test_dir"
}

# =============================================================================
# Main
# =============================================================================

echo "=== Wave-Based Cross-Validation Tests ==="
echo ""

run_test test_wave_calculation
run_test test_wave_calculation_exact
run_test test_wave_calculation_small
run_test test_fingerprint_splitting
run_test test_wave_stats_json
run_test test_wave_retry_bounds
run_test test_line_range_extraction

echo ""
echo "=== Summary ==="
echo "Tests run: $TESTS_RUN"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"

if [[ $TESTS_FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
