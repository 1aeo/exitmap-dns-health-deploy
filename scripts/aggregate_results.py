#!/usr/bin/env python3
"""
Aggregate per-relay DNS health results into a single report.

Usage:
    python3 aggregate_results.py --input ./results_dir --output ./report.json

Cross-validation mode:
    python3 aggregate_results.py --input ./merged --output ./report.json \
        --cross-validate --source ./cv1 --source ./cv2 --source ./cv3
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from collections import Counter


# Cross-validation: when multiple instances test the same relay,
# pick the result with the lowest priority number as the "best" result.
# This doesn't drop other results - it just selects which one to use as primary.
CROSS_VALIDATION_RESULT_PRIORITY = {
    "success": 0,           # Best - always prefer success
    "wrong_ip": 1,          # Definitive DNS failure
    "dns_fail": 2,          # Definitive DNS failure
    "socks_error": 3,       # May be transient
    "network_error": 4,     # May be transient
    "error": 5,             # Generic error
    "timeout": 6,           # Often transient
    "hard_timeout": 6,      # Same priority as timeout
    "exception": 7,         # Code error
    "unknown": 8,           # Unknown status
    "relay_unreachable": 9, # Circuit failure - not a DNS test result
}


# All 17 circuit failure types for explicit zeros in output
CIRCUIT_FAILURE_TYPES = [
    "circuit_timeout",
    "circuit_destroyed",
    "circuit_channel_closed",
    "circuit_connect_failed",
    "circuit_no_path",
    "circuit_resource_limit",
    "circuit_hibernating",
    "circuit_finished",
    "circuit_connection_closed",
    "circuit_io_error",
    "circuit_protocol_error",
    "circuit_internal_error",
    "circuit_requested",
    "circuit_no_service",
    "circuit_measurement_expired",
    "circuit_guard_limit",
    "circuit_failed",
]


# Mapping from raw circuit_reason values to normalized JSON keys
CIRCUIT_REASON_MAP = {
    "circuit_timeout": "circuit_timeout",
    "circuit_destroyed": "circuit_destroyed",
    "channel_closed": "circuit_channel_closed",
    "relay_connect_failed": "circuit_connect_failed",
    "circuit_no_path": "circuit_no_path",
    "relay_resource_limit": "circuit_resource_limit",
    "relay_hibernating": "circuit_hibernating",
    "circuit_finished": "circuit_finished",
    "relay_connection_closed": "circuit_connection_closed",
    "io_error": "circuit_io_error",
    "tor_protocol_error": "circuit_protocol_error",
    "tor_internal_error": "circuit_internal_error",
    "circuit_requested": "circuit_requested",
    "no_such_service": "circuit_no_service",
    "measurement_expired": "circuit_measurement_expired",
    "guard_limit": "circuit_guard_limit",
    "circuit_failed": "circuit_failed",
}


def _load_json_file(fpath):
    """Load a single JSON file, return None on error."""
    try:
        with open(fpath) as f:
            return json.load(f)
    except Exception as e:
        print("Warning: Could not read %s: %s" % (fpath, e))
        return None


def _find_json_files(directory, filename, recursive=False):
    """
    Find all instances of a specific JSON file in directory.
    
    Args:
        directory: Root directory to search
        filename: Name of file to find (e.g., "scan_stats.json")
        recursive: If True, search all subdirectories
    
    Yields:
        Full paths to matching files
    """
    if not os.path.isdir(directory):
        return
    
    if recursive:
        for root, _, files in os.walk(directory):
            if filename in files:
                yield os.path.join(root, filename)
    else:
        # Check nested timestamp directories first
        for entry in os.listdir(directory):
            subdir = os.path.join(directory, entry)
            if os.path.isdir(subdir):
                fpath = os.path.join(subdir, filename)
                if os.path.exists(fpath):
                    yield fpath
        # Also check root directory
        fpath = os.path.join(directory, filename)
        if os.path.exists(fpath):
            yield fpath


def _iter_result_files(directory, recursive=False):
    """Iterate over dnshealth_*.json files in a directory."""
    if not os.path.isdir(directory):
        return
    
    if recursive:
        for root, _, files in os.walk(directory):
            for fname in files:
                if fname.startswith("dnshealth_") and fname.endswith(".json"):
                    yield os.path.join(root, fname)
    else:
        for fname in os.listdir(directory):
            if fname.startswith("dnshealth_") and fname.endswith(".json"):
                yield os.path.join(directory, fname)


def load_scan_stats(directory, recursive=False):
    """Load scan_stats.json from directory, returning aggregated stats."""
    totals = {"total_circuits": 0, "successful_circuits": 0, "failed_circuits": 0}
    
    for fpath in _find_json_files(directory, "scan_stats.json", recursive):
        data = _load_json_file(fpath)
        if data:
            for key in totals:
                totals[key] += data.get(key, 0)
            print("Loaded scan stats from %s: %d total, %d successful, %d failed" % (
                fpath, data.get("total_circuits", 0), 
                data.get("successful_circuits", 0), 
                data.get("failed_circuits", 0)))
    
    return totals


def load_circuit_failures(directory, recursive=False):
    """Load circuit_failures.json from directory, returning list of failure entries."""
    failures = []
    
    for fpath in _find_json_files(directory, "circuit_failures.json", recursive):
        data = _load_json_file(fpath)
        if data and isinstance(data, list):
            failures.extend(data)
            print("Loaded %d circuit failures with fingerprints from %s" % (len(data), fpath))
    
    return failures


def load_results(input_dir):
    """Load all dnshealth_*.json files from input directory."""
    if not os.path.isdir(input_dir):
        print("Error: %s is not a directory" % input_dir)
        return []

    # Check for nested timestamp directories
    subdirs = [d for d in os.listdir(input_dir)
               if os.path.isdir(os.path.join(input_dir, d)) and "dnshealth" in d]
    if subdirs:
        subdirs.sort(reverse=True)
        input_dir = os.path.join(input_dir, subdirs[0])
        print("Using results from: %s" % input_dir)

    results = []
    for fpath in _iter_result_files(input_dir):
        result = _load_json_file(fpath)
        if result:
            results.append(result)
    return results


def _get_instance_name(source_dir):
    """Extract instance name from source directory path."""
    # /path/to/analysis_2026-01-17_15-49-26_cv2 -> cv2
    basename = os.path.basename(source_dir.rstrip('/'))
    parts = basename.split('_')
    return parts[-1] if parts else basename


def _extract_instance_detail(result):
    """Extract relevant fields from a result based on its status."""
    status = result.get("status", "unknown")
    detail = {"status": status}
    
    # Copy relevant fields if present (avoids repetitive if-blocks)
    # Keys included per status: attempt (always), timing (all), resolved_ip, expected_ip, error
    for key in ("attempt", "timing", "resolved_ip", "expected_ip", "error"):
        if result.get(key):
            detail[key] = result[key]
    
    return detail


def load_all_source_results(source_dirs):
    """Load results from multiple source directories, tracking instance names."""
    all_results = {}  # fingerprint -> {instance_name: result}
    instance_names = []
    
    for source_dir in source_dirs:
        instance_name = _get_instance_name(source_dir)
        instance_names.append(instance_name)
        
        for fpath in _iter_result_files(source_dir, recursive=True):
            result = _load_json_file(fpath)
            if result:
                fp = result.get("exit_fingerprint")
                if fp:
                    all_results.setdefault(fp, {})[instance_name] = result
    
    return all_results, instance_names


def cross_validate_results(source_dirs):
    """
    Cross-validate results from multiple sources with full per-instance details.
    
    For each relay, keep the BEST result (success beats timeout, etc.)
    This allows transient failures in one instance to be recovered by success in another.
    Each relay gets a 'cv' field with per-instance breakdown.
    """
    all_results, instance_names = load_all_source_results(source_dirs)
    
    merged = []
    cv_stats = {
        "improved": 0,
        "instances": len(source_dirs),
        "instance_names": instance_names,
        "recovered_from_timeout": 0,
        "recovered_from_dns_fail": 0,
        "recovered_from_error": 0,
        "consistency": {"all_success": 0, "all_failed": 0, "mixed": 0},
        "per_instance_stats": {name: Counter() for name in instance_names},
    }
    
    for fp, instance_results in all_results.items():
        if not instance_results:
            continue
        
        # Build per-instance details and track stats
        per_instance = {}
        for inst_name, result in instance_results.items():
            status = result.get("status", "unknown")
            cv_stats["per_instance_stats"][inst_name][status] += 1
            per_instance[inst_name] = _extract_instance_detail(result)
        
        # Find best result (sort by cross-validation result priority)
        sorted_results = sorted(
            instance_results.items(),
            key=lambda x: CROSS_VALIDATION_RESULT_PRIORITY.get(x[1].get("status", "unknown"), 99)
        )
        best_inst, best_result = sorted_results[0]
        
        # Calculate consistency stats
        statuses = [r.get("status") for r in instance_results.values()]
        success_count = statuses.count("success")
        
        if success_count == len(statuses):
            cv_stats["consistency"]["all_success"] += 1
        elif success_count == 0:
            cv_stats["consistency"]["all_failed"] += 1
        else:
            cv_stats["consistency"]["mixed"] += 1
        
        # Calculate average timing across successful instances
        successful_timings = [
            r.get("timing") for r in instance_results.values()
            if r.get("status") == "success" and r.get("timing")
        ]
        if successful_timings:
            # Average total timing
            total_values = [t.get("total_ms") for t in successful_timings if t.get("total_ms") is not None]
            avg_timing = {"total_ms": round(sum(total_values) / len(total_values)) if total_values else None}
            best_result["timing"] = avg_timing
        
        # Build CV details for this relay
        cv_detail = {
            "result_source": best_inst,
            "instances_success": success_count,
            "instances_total": len(instance_results),
            "improved": success_count > 0 and success_count < len(statuses),
            "per_instance": per_instance,
        }
        
        # Track improvements and what we recovered from
        if cv_detail["improved"]:
            cv_stats["improved"] += 1
            recovered_from = []
            for s in statuses:
                if s != "success":
                    recovered_from.append(s)
                    if s in ("timeout", "hard_timeout"):
                        cv_stats["recovered_from_timeout"] += 1
                    elif s == "dns_fail":
                        cv_stats["recovered_from_dns_fail"] += 1
                    else:
                        cv_stats["recovered_from_error"] += 1
            cv_detail["recovered_from"] = recovered_from
        
        # Add CV details to best result
        best_result["cv"] = cv_detail
        merged.append(best_result)
    
    # Print summary
    print(f"Cross-validation: {cv_stats['improved']} relays improved")
    print(f"  - Recovered from timeout: {cv_stats['recovered_from_timeout']}")
    print(f"  - Recovered from DNS fail: {cv_stats['recovered_from_dns_fail']}")
    print(f"  - Recovered from other errors: {cv_stats['recovered_from_error']}")
    print(f"Consistency: {cv_stats['consistency']['all_success']} all-success, "
          f"{cv_stats['consistency']['all_failed']} all-failed, "
          f"{cv_stats['consistency']['mixed']} mixed")
    return merged, cv_stats


def _compute_single_latency_stats(values):
    """Compute statistics from a list of values (sorts in-place). Returns None if empty."""
    if not values:
        return None
    
    values.sort()  # In-place sort to avoid creating new list
    n = len(values)
    return {
        "avg_ms": round(sum(values) / n),
        "min_ms": values[0],
        "max_ms": values[-1],
        "p50_ms": values[n // 2],
        "p95_ms": values[int(n * 0.95)],
        "p99_ms": values[int(n * 0.99)],
    }


def compute_latency_stats(timings):
    """
    Compute latency statistics from a list of timing dicts.
    
    Args:
        timings: List of timing dicts with {total_ms, socket_ms, dns_ms}
    
    Returns:
        Dict with stats for each timing type: {total: {...}, socket: {...}, dns: {...}}
    """
    if not timings:
        return {
            "total": {"avg_ms": 0, "min_ms": 0, "max_ms": 0, "p50_ms": 0, "p95_ms": 0, "p99_ms": 0},
            "socket": None,
            "dns": None,
        }
    
    # Extract total timing (includes Tor circuit + DNS resolution)
    totals = [t.get("total_ms") for t in timings if t and t.get("total_ms") is not None]
    
    return {
        "total": _compute_single_latency_stats(totals) or {"avg_ms": 0, "min_ms": 0, "max_ms": 0, "p50_ms": 0, "p95_ms": 0, "p99_ms": 0},
    }


def _normalize_circuit_reason(reason):
    """Normalize circuit_reason to standard circuit_* key."""
    return CIRCUIT_REASON_MAP.get(reason, "circuit_failed")


def _order_result_fields(result):
    """Return result dict with fields in standard order, removing per-run constants."""
    # Standard field order per plan
    ordered = {}
    
    # 1-3: Identity fields
    if "exit_fingerprint" in result:
        ordered["exit_fingerprint"] = result["exit_fingerprint"]
    if "exit_nickname" in result:
        ordered["exit_nickname"] = result["exit_nickname"]
    if "exit_address" in result:
        ordered["exit_address"] = result["exit_address"]
    
    # 4: Status
    if "status" in result:
        ordered["status"] = result["status"]
    
    # 5-6: IP resolution
    if "resolved_ip" in result:
        ordered["resolved_ip"] = result["resolved_ip"]
    if "expected_ip" in result:
        ordered["expected_ip"] = result["expected_ip"]
    
    # 7-8: Query details
    if "query_domain" in result:
        ordered["query_domain"] = result["query_domain"]
    if "first_hop" in result:
        ordered["first_hop"] = result["first_hop"]
    
    # 9-12: Timing and metadata
    if "timing" in result:
        ordered["timing"] = result["timing"]
    if "timestamp" in result:
        ordered["timestamp"] = result["timestamp"]
    if "attempt" in result:
        ordered["attempt"] = result["attempt"]
    if "consecutive_failures" in result:
        ordered["consecutive_failures"] = result["consecutive_failures"]
    
    # 13: Error
    if "error" in result:
        ordered["error"] = result["error"]
    
    # 14: Cross-validation details (if present)
    if "cv" in result:
        ordered["cv"] = result["cv"]
    
    # Note: tor_metrics_url, mode, run_id are NOT included (moved to metadata or derivable)
    
    return ordered


def aggregate_results(results, previous_report=None, circuit_failures=None, scan_stats=None,
                      scan_type="single", scan_instances=1, instance_names=None):
    """Aggregate results into a summary report (single pass)."""
    # Load previous state for consecutive failure tracking
    prev_state = {}
    if previous_report and os.path.exists(previous_report):
        try:
            with open(previous_report) as f:
                for r in json.load(f).get("results", []):
                    fp = r.get("exit_fingerprint")
                    if fp:
                        prev_state[fp] = r
        except Exception as e:
            print("Warning: Could not load previous report: %s" % e)

    # Merge circuit failures into results (if any)
    # Track which fingerprints we've already seen from DNS results
    dns_fingerprints = {r.get("exit_fingerprint") for r in results}
    circuit_counts = Counter()  # Normalized circuit_* keys
    
    if circuit_failures:
        for cf in circuit_failures:
            fp = cf.get("exit_fingerprint")
            # Only add if not already in DNS results (avoid duplicates)
            if fp and fp not in dns_fingerprints:
                results.append(cf)
                dns_fingerprints.add(fp)
                # Track circuit failure reasons (normalize to circuit_* keys)
                # Only count circuit failures that are actually added (not filtered duplicates)
                raw_reason = cf.get("circuit_reason", "circuit_failed")
                normalized_key = _normalize_circuit_reason(raw_reason)
                circuit_counts[normalized_key] += 1

    # Extract run_id and mode from first result (same for all)
    run_id = None
    mode = "wildcard"
    if results:
        first_result = results[0]
        run_id = first_result.get("run_id")
        mode = first_result.get("mode", "wildcard")

    # Single-pass aggregation
    stats = Counter()
    timings = []
    processed_results = []

    for r in results:
        status = r.get("status", "unknown")
        stats[status] += 1
        fp = r.get("exit_fingerprint")

        # Track consecutive failures
        if status == "success":
            r["consecutive_failures"] = 0
            if r.get("timing"):
                timings.append(r["timing"])
        else:
            prev = prev_state.get(fp, {})
            prev_failures = prev.get("consecutive_failures", 0) if prev.get("status") != "success" else 0
            r["consecutive_failures"] = prev_failures + 1

        # Order fields and remove per-run constants
        processed_results.append(_order_result_fields(r))

    # Calculate totals and rates from actual results (source of truth)
    total = len(results)
    unreachable_relays = stats.get("relay_unreachable", 0)
    tested_relays = total - unreachable_relays
    
    # Use scan_stats for consensus count only (total attempted)
    if scan_stats and scan_stats.get("total_circuits", 0) > 0:
        consensus_relays = scan_stats["total_circuits"]
        # Log if there's a discrepancy
        expected_total = scan_stats["successful_circuits"] + scan_stats["failed_circuits"]
        if total != expected_total:
            print("Warning: scan_stats expected %d results, but only %d files found (missing %d)" % (
                expected_total, total, expected_total - total))
    else:
        consensus_relays = total
    
    print("Counts: %d consensus, %d tested, %d unreachable (from %d result files)" % (
        consensus_relays, tested_relays, unreachable_relays, total))
    
    dns_success = stats.get("success", 0)
    
    # Two success rates
    dns_success_rate = (dns_success / tested_relays * 100) if tested_relays else 0
    reachability_rate = (tested_relays / consensus_relays * 100) if consensus_relays else 0
    
    timing_stats = compute_latency_stats(timings)

    # Build metadata with new schema
    metadata = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "run_id": run_id,
        "mode": mode,
        
        # Scan configuration
        "scan": {
            "type": scan_type,
            "instances": scan_instances,
            "instance_names": instance_names or [],
        },
        
        # Relay counts
        "consensus_relays": consensus_relays,
        "tested_relays": tested_relays,
        "unreachable_relays": unreachable_relays,
        
        # DNS test results (all categories with dns_ prefix)
        "dns_success": dns_success,
        "dns_fail": stats.get("dns_fail", 0),
        "dns_timeout": stats.get("timeout", 0) + stats.get("hard_timeout", 0),
        "dns_wrong_ip": stats.get("wrong_ip", 0),
        "dns_socks_error": stats.get("socks_error", 0),
        "dns_network_error": stats.get("network_error", 0) + stats.get("tor_connection_refused", 0) + stats.get("tor_connection_lost", 0) + stats.get("eof_error", 0),
        "dns_error": stats.get("error", 0),
        "dns_exception": stats.get("exception", 0),
        "dns_unknown": stats.get("unknown", 0),
    }
    
    # Add all 17 circuit failure types with explicit zeros
    for circuit_type in CIRCUIT_FAILURE_TYPES:
        metadata[circuit_type] = circuit_counts.get(circuit_type, 0)
    
    # Add rates and timing
    metadata["dns_success_rate_percent"] = round(dns_success_rate, 2)
    metadata["reachability_rate_percent"] = round(reachability_rate, 2)
    metadata["timing"] = timing_stats

    return {
        "metadata": metadata,
        "results": processed_results,
    }


def _fmt_timing_line(label, stats):
    """Format a single timing stats line."""
    if not stats:
        return "  %s: (no data)" % label
    return "  %s: Avg %d ms | Min %d ms | Max %d ms | P50 %d ms | P95 %d ms | P99 %d ms" % (
        label, stats["avg_ms"], stats["min_ms"], stats["max_ms"],
        stats["p50_ms"], stats["p95_ms"], stats["p99_ms"])


def print_summary(report):
    """Print a human-readable summary."""
    m = report["metadata"]
    timing = m.get("timing", {})

    print("\n" + "=" * 60)
    print("DNS HEALTH VALIDATION SUMMARY")
    print("=" * 60)
    print("Timestamp: %s" % m["timestamp"])
    
    # Scan info
    scan = m.get("scan", {})
    if scan:
        print("Scan: %s mode, %d instance(s)" % (scan.get("type", "single"), scan.get("instances", 1)))
    print()
    
    # Relay counts
    consensus = m.get("consensus_relays", 0)
    tested = m.get("tested_relays", 0)
    unreachable = m.get("unreachable_relays", 0)
    print("RELAY COUNTS:")
    print("  Consensus Relays:    %5d" % consensus)
    print("  Tested (reachable):  %5d  (%.2f%%)" % (tested, m.get("reachability_rate_percent", 0)))
    print("  Unreachable Relays:  %5d" % unreachable)
    print()
    
    print("DNS TEST RESULTS (of %d tested relays):" % tested)
    print("  Success:       %5d  (%.2f%%)" % (m.get("dns_success", 0), m.get("dns_success_rate_percent", 0)))
    print("  DNS Fail:      %5d" % m.get("dns_fail", 0))
    print("  Wrong IP:      %5d" % m.get("dns_wrong_ip", 0))
    print("  Timeout:       %5d" % m.get("dns_timeout", 0))
    print("  SOCKS Error:   %5d" % m.get("dns_socks_error", 0))
    print("  Network Error: %5d" % m.get("dns_network_error", 0))
    print("  Other Error:   %5d" % m.get("dns_error", 0))
    print("  Exception:     %5d" % m.get("dns_exception", 0))
    
    # Circuit failure breakdown (from flat circuit_* fields)
    if unreachable > 0:
        print()
        print("CIRCUIT FAILURES (%d total):" % unreachable)
        for circuit_type in CIRCUIT_FAILURE_TYPES:
            count = m.get(circuit_type, 0)
            if count > 0:
                print("  %-30s %5d" % (circuit_type + ":", count))
    print()
    
    # Cross-validation details
    cv = m.get("cross_validation", {})
    scan_type = m.get("scan", {}).get("type", "single")
    if scan_type == "cross_validate" and cv:
        scan_info = m.get("scan", {})
        print("CROSS-VALIDATION (%d instances):" % scan_info.get("instances", 0))
        print("  Instances: %s" % ", ".join(scan_info.get("instance_names", [])))
        cons = cv.get("consistency", {})
        print("  Consistency: %d all-success, %d all-failed, %d mixed" % (
            cons.get("all_success", 0), cons.get("all_failed", 0), cons.get("mixed", 0)))
        print("  Relays improved: %d" % cv.get("relays_improved", 0))
        print("    - Recovered from timeout: %d" % cv.get("recovered_from_timeout", 0))
        print("    - Recovered from DNS fail: %d" % cv.get("recovered_from_dns_fail", 0))
        print("    - Recovered from other: %d" % cv.get("recovered_from_error", 0))
        
        # Per-instance stats
        per_inst = cv.get("per_instance_stats", {})
        if per_inst:
            print("  Per-instance results:")
            for inst_name in sorted(per_inst.keys()):
                stats = per_inst[inst_name]
                success = stats.get("success", 0)
                total = sum(stats.values())
                print("    %s: %d/%d success (%.1f%%)" % (
                    inst_name, success, total, (success/total*100) if total else 0))
        print()
    
    print("TIMING STATISTICS (successful resolutions):")
    print(_fmt_timing_line("Total (circuit + DNS)", timing.get("total")))
    print()

    # Compute failures from results (no longer stored separately)
    results = report.get("results", [])
    failures = [r for r in results if r.get("status") != "success"]
    if failures:
        print("FAILED RELAYS (%d):" % len(failures))
        for f in failures[:20]:
            print("  - %-20s (%s...) [%s] %s" % (
                f.get("exit_nickname", "unknown")[:20],
                f.get("exit_fingerprint", "????????")[:8],
                f.get("status"),
                (f.get("error") or "")[:40]
            ))
        if len(failures) > 20:
            print("  ... and %d more failures" % (len(failures) - 20))
    else:
        print("No failures detected!")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Aggregate DNS health results")
    parser.add_argument("--input", "-i", required=True, help="Input directory")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file")
    parser.add_argument("--previous", "-p", help="Previous report for tracking")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress summary")
    parser.add_argument("--cross-validate", "-c", action="store_true",
                        help="Enable cross-validation mode (best result wins)")
    parser.add_argument("--source", "-s", action="append", dest="sources",
                        help="Source directory for cross-validation (can repeat)")
    parser.add_argument("--scan-type", default="single",
                        choices=["single", "cross_validate", "split"],
                        help="Scan mode type for metadata")
    parser.add_argument("--scan-instances", type=int, default=1,
                        help="Number of instances used in scan")
    args = parser.parse_args()

    cv_stats = None
    circuit_failures = []
    scan_stats = {"total_circuits": 0, "successful_circuits": 0, "failed_circuits": 0}
    
    if args.cross_validate and args.sources:
        # Cross-validation mode: merge best results from multiple sources
        results, cv_stats = cross_validate_results(args.sources)
        if not results:
            print("No results found in source directories")
            return 1
        print("Cross-validated %d unique relays from %d sources" % (len(results), len(args.sources)))
        # Load scan stats and circuit failures from all source directories
        for source_dir in args.sources:
            source_scan_stats = load_scan_stats(source_dir, recursive=True)
            # For cross-validation, take max of total_circuits (should be same across instances)
            if source_scan_stats["total_circuits"] > scan_stats["total_circuits"]:
                scan_stats["total_circuits"] = source_scan_stats["total_circuits"]
            # Sum the successful and failed counts (will be divided later for average if needed)
            scan_stats["successful_circuits"] = max(scan_stats["successful_circuits"], 
                                                     source_scan_stats["successful_circuits"])
            scan_stats["failed_circuits"] = min(scan_stats["failed_circuits"] or source_scan_stats["failed_circuits"],
                                                 source_scan_stats["failed_circuits"]) if scan_stats["failed_circuits"] else source_scan_stats["failed_circuits"]
            circuit_failures.extend(load_circuit_failures(source_dir, recursive=True))
    else:
        # Standard mode: load from single input directory
        results = load_results(args.input)
        if not results:
            print("No results found in %s" % args.input)
            return 1
        print("Loaded %d results" % len(results))
        # Load scan stats and circuit failures from input directory
        scan_stats = load_scan_stats(args.input)
        circuit_failures = load_circuit_failures(args.input)
    
    # Deduplicate circuit failures by fingerprint
    if circuit_failures:
        seen_fps = set()
        unique_failures = []
        for cf in circuit_failures:
            fp = cf.get("exit_fingerprint")
            if fp and fp not in seen_fps:
                unique_failures.append(cf)
                seen_fps.add(fp)
        circuit_failures = unique_failures
        print("Total circuit failures with fingerprints: %d" % len(circuit_failures))

    # Determine instance names for scan metadata
    instance_names = []
    if cv_stats:
        instance_names = cv_stats.get("instance_names", [])
    elif args.scan_instances > 1:
        # Generate default names for split mode
        instance_names = [f"split{i}" for i in range(1, args.scan_instances + 1)]
    
    report = aggregate_results(
        results, args.previous, circuit_failures, scan_stats,
        scan_type=args.scan_type,
        scan_instances=args.scan_instances,
        instance_names=instance_names
    )
    
    # Add cross-validation metadata if applicable
    if cv_stats:
        report["metadata"]["cross_validation"] = {
            "relays_improved": cv_stats["improved"],
            "recovered_from_timeout": cv_stats.get("recovered_from_timeout", 0),
            "recovered_from_dns_fail": cv_stats.get("recovered_from_dns_fail", 0),
            "recovered_from_error": cv_stats.get("recovered_from_error", 0),
            "consistency": cv_stats.get("consistency", {}),
            "per_instance_stats": {
                name: dict(counts) 
                for name, counts in cv_stats.get("per_instance_stats", {}).items()
            },
        }

    with open(args.output, "w") as f:
        json.dump(report, f)
    print("Report written to: %s" % args.output)

    if not args.quiet:
        print_summary(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
