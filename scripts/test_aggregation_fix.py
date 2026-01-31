#!/usr/bin/env python3
"""
Test script to verify the circuit_counts fix in aggregate_results.py

This simulates the cross-validation scenario where:
- Instance 1 successfully tests some relays
- Instance 2 fails to reach some of the same relays (circuit failures)

The fix ensures that circuit_counts only includes unique circuit failures
that are actually added to results (not filtered duplicates).
"""
import json
import os
import sys
import tempfile
import shutil

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aggregate_results import aggregate_results, load_circuit_failures, CIRCUIT_FAILURE_TYPES


def create_test_data():
    """Create mock DNS results and circuit failures for testing."""
    
    # Simulate DNS results (relays that were successfully reached and tested)
    dns_results = [
        # 10 successful DNS tests
        {"exit_fingerprint": f"FP_SUCCESS_{i}", "exit_nickname": f"SuccessRelay{i}", 
         "status": "success", "timing": {"total_ms": 1000}} 
        for i in range(10)
    ] + [
        # 3 DNS failures (reached relay but DNS failed)
        {"exit_fingerprint": f"FP_DNSFAIL_{i}", "exit_nickname": f"DNSFailRelay{i}",
         "status": "dns_fail", "error": "DNS Error: SOCKS 4 - Domain not found"}
        for i in range(3)
    ]
    
    # Simulate circuit failures
    # Include some relays that are ALSO in DNS results (should be filtered)
    # and some that are NOT in DNS results (should be counted)
    circuit_failures = [
        # 5 unique circuit failures (relays not in DNS results)
        {"exit_fingerprint": f"FP_UNREACHABLE_{i}", "exit_nickname": f"UnreachableRelay{i}",
         "status": "relay_unreachable", "circuit_reason": "circuit_timeout",
         "error": "Tor Circuit Error: Construction timed out"}
        for i in range(5)
    ] + [
        # 3 DUPLICATE circuit failures for relays that ARE in DNS results
        # These should be filtered out and NOT counted
        {"exit_fingerprint": f"FP_SUCCESS_{i}", "exit_nickname": f"SuccessRelay{i}",
         "status": "relay_unreachable", "circuit_reason": "circuit_timeout",
         "error": "Tor Circuit Error: Construction timed out"}
        for i in range(3)
    ] + [
        # 2 more DUPLICATE circuit failures for DNS fail relays
        {"exit_fingerprint": f"FP_DNSFAIL_{i}", "exit_nickname": f"DNSFailRelay{i}",
         "status": "relay_unreachable", "circuit_reason": "relay_connect_failed",
         "error": "Tor Circuit Error: Could not connect to relay"}
        for i in range(2)
    ]
    
    return dns_results, circuit_failures


def test_aggregation():
    """Test that the aggregation correctly handles duplicate circuit failures."""
    
    print("=" * 70)
    print("Testing aggregate_results fix for circuit_counts")
    print("=" * 70)
    
    dns_results, circuit_failures = create_test_data()
    
    print(f"\nTest data:")
    print(f"  - DNS results: {len(dns_results)} (10 success + 3 dns_fail)")
    print(f"  - Circuit failures: {len(circuit_failures)} total")
    print(f"    - 5 unique (not in DNS results)")
    print(f"    - 5 duplicates (already in DNS results, should be filtered)")
    
    # Run aggregation
    report = aggregate_results(
        results=dns_results.copy(),  # Copy to avoid mutation
        circuit_failures=circuit_failures,
        scan_type="cross_validate",
        scan_instances=2,
        instance_names=["cv1", "cv2"]
    )
    
    metadata = report["metadata"]
    results = report["results"]
    
    print(f"\nResults:")
    print(f"  - Total results: {len(results)}")
    print(f"  - unreachable_relays: {metadata['unreachable_relays']}")
    
    # Calculate sum of circuit_* counts
    circuit_sum = sum(metadata.get(ct, 0) for ct in CIRCUIT_FAILURE_TYPES)
    print(f"  - Sum of circuit_* counts: {circuit_sum}")
    
    # Show breakdown
    print(f"\n  Circuit failure breakdown:")
    for ct in CIRCUIT_FAILURE_TYPES:
        count = metadata.get(ct, 0)
        if count > 0:
            print(f"    - {ct}: {count}")
    
    # Verify the fix
    print(f"\n" + "=" * 70)
    print("VERIFICATION:")
    print("=" * 70)
    
    # Expected: 5 unique unreachable relays, not 10 (with duplicates)
    expected_unreachable = 5
    expected_circuit_sum = 5
    expected_total = 13 + 5  # 13 DNS results + 5 unique circuit failures
    
    errors = []
    
    if metadata['unreachable_relays'] != expected_unreachable:
        errors.append(f"unreachable_relays: expected {expected_unreachable}, got {metadata['unreachable_relays']}")
    
    if circuit_sum != expected_circuit_sum:
        errors.append(f"circuit_* sum: expected {expected_circuit_sum}, got {circuit_sum}")
    
    if len(results) != expected_total:
        errors.append(f"total results: expected {expected_total}, got {len(results)}")
    
    # The key check: circuit_sum should equal unreachable_relays
    if circuit_sum != metadata['unreachable_relays']:
        errors.append(f"MISMATCH: circuit_* sum ({circuit_sum}) != unreachable_relays ({metadata['unreachable_relays']})")
    
    if errors:
        print("\n❌ FAILED - Issues found:")
        for err in errors:
            print(f"  - {err}")
        return False
    else:
        print("\n✅ PASSED - All checks passed!")
        print(f"  - unreachable_relays = {metadata['unreachable_relays']} (correct)")
        print(f"  - circuit_* sum = {circuit_sum} (matches unreachable_relays)")
        print(f"  - Duplicate circuit failures were correctly filtered")
        return True


def test_single_mode():
    """Test single mode (non-cross-validation) to ensure it still works."""
    
    print("\n" + "=" * 70)
    print("Testing single mode (no duplicates expected)")
    print("=" * 70)
    
    # In single mode, there should be no duplicate circuit failures
    dns_results = [
        {"exit_fingerprint": f"FP_SUCCESS_{i}", "exit_nickname": f"SuccessRelay{i}",
         "status": "success", "timing": {"total_ms": 1000}}
        for i in range(10)
    ]
    
    circuit_failures = [
        {"exit_fingerprint": f"FP_UNREACHABLE_{i}", "exit_nickname": f"UnreachableRelay{i}",
         "status": "relay_unreachable", "circuit_reason": "circuit_timeout"}
        for i in range(5)
    ]
    
    report = aggregate_results(
        results=dns_results.copy(),
        circuit_failures=circuit_failures,
        scan_type="single",
        scan_instances=1
    )
    
    metadata = report["metadata"]
    circuit_sum = sum(metadata.get(ct, 0) for ct in CIRCUIT_FAILURE_TYPES)
    
    print(f"\nResults:")
    print(f"  - unreachable_relays: {metadata['unreachable_relays']}")
    print(f"  - circuit_* sum: {circuit_sum}")
    
    if metadata['unreachable_relays'] == 5 and circuit_sum == 5:
        print("\n✅ PASSED - Single mode works correctly")
        return True
    else:
        print("\n❌ FAILED - Single mode issue")
        return False


if __name__ == "__main__":
    passed = test_aggregation() and test_single_mode()
    
    print("\n" + "=" * 70)
    if passed:
        print("ALL TESTS PASSED")
    else:
        print("SOME TESTS FAILED")
    print("=" * 70)
    
    sys.exit(0 if passed else 1)
