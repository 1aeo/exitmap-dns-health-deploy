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


# Priority for cross-validation: success beats everything
STATUS_PRIORITY = {
    "success": 0,      # Best - always keep
    "wrong_ip": 1,     # Keep - definitive failure
    "dns_fail": 2,     # Keep - definitive failure
    "socks_error": 3,  # May be transient
    "network_error": 4,
    "error": 5,
    "timeout": 6,      # Often transient
    "exception": 7,
    "unknown": 8,
}


def _load_json_file(fpath):
    """Load a single JSON file, return None on error."""
    try:
        with open(fpath) as f:
            return json.load(f)
    except Exception as e:
        print("Warning: Could not read %s: %s" % (fpath, e))
        return None


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
    # Keys included per status: attempt (always), latency_ms (all), resolved_ip, expected_ip, error
    for key in ("attempt", "latency_ms", "resolved_ip", "expected_ip", "error"):
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
        
        # Find best result (sort by status priority)
        sorted_results = sorted(
            instance_results.items(),
            key=lambda x: STATUS_PRIORITY.get(x[1].get("status", "unknown"), 99)
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


def compute_latency_stats(latencies):
    """Compute latency statistics from a list of values (sorts in-place)."""
    if not latencies:
        return {"avg_ms": 0, "min_ms": 0, "max_ms": 0, "p50_ms": 0, "p95_ms": 0, "p99_ms": 0}
    
    latencies.sort()  # In-place sort to avoid creating new list
    n = len(latencies)
    return {
        "avg_ms": round(sum(latencies) / n),
        "min_ms": latencies[0],
        "max_ms": latencies[-1],
        "p50_ms": latencies[n // 2],
        "p95_ms": latencies[int(n * 0.95)],
        "p99_ms": latencies[int(n * 0.99)],
    }


def aggregate_results(results, previous_report=None):
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

    # Single-pass aggregation
    stats = Counter()
    latencies = []
    failures = []
    failures_by_ip = {}

    for r in results:
        status = r.get("status", "unknown")
        stats[status] += 1
        fp = r.get("exit_fingerprint")

        # Track consecutive failures
        if status == "success":
            r["consecutive_failures"] = 0
            if r.get("latency_ms"):
                latencies.append(r["latency_ms"])
        else:
            prev = prev_state.get(fp, {})
            prev_failures = prev.get("consecutive_failures", 0) if prev.get("status") != "success" else 0
            r["consecutive_failures"] = prev_failures + 1

            # Build failure entry (only for non-success)
            failures.append(r)
            ip = r.get("exit_address", "unknown")
            failures_by_ip.setdefault(ip, []).append({
                "fingerprint": fp,
                "nickname": r.get("exit_nickname", "unknown"),
                "status": status,
                "error": r.get("error")
            })

    total = len(results)
    success = stats.get("success", 0)
    success_rate = (success / total * 100) if total else 0
    lat_stats = compute_latency_stats(latencies)

    return {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "total_relays": total,
            "success": success,
            "wrong_ip": stats.get("wrong_ip", 0),
            "dns_fail": stats.get("dns_fail", 0),
            "timeout": stats.get("timeout", 0),
            "error": stats.get("error", 0),
            "socks_error": stats.get("socks_error", 0),
            "network_error": stats.get("network_error", 0),
            "exception": stats.get("exception", 0),
            "unknown": stats.get("unknown", 0),
            "success_rate_percent": round(success_rate, 2),
            "latency": lat_stats
        },
        "results": results,
        "failures": failures,
        "failures_by_ip": failures_by_ip,
    }


def print_summary(report):
    """Print a human-readable summary."""
    m = report["metadata"]
    lat = m["latency"]

    print("\n" + "=" * 60)
    print("DNS HEALTH VALIDATION SUMMARY")
    print("=" * 60)
    print("Timestamp: %s" % m["timestamp"])
    print("Total Relays: %d" % m["total_relays"])
    print()
    print("STATUS BREAKDOWN:")
    print("  Success:       %5d  (%.2f%%)" % (m["success"], m["success_rate_percent"]))
    print("  DNS Fail:      %5d" % m["dns_fail"])
    print("  Wrong IP:      %5d" % m["wrong_ip"])
    print("  Timeout:       %5d" % m["timeout"])
    print("  SOCKS Error:   %5d" % m["socks_error"])
    print("  Network Error: %5d" % m["network_error"])
    print("  Other Error:   %5d" % m["error"])
    print("  Exception:     %5d" % m["exception"])
    print()
    
    # Cross-validation details
    cv = m.get("cross_validation", {})
    if cv.get("enabled"):
        print("CROSS-VALIDATION (%d instances):" % cv.get("instances", 0))
        print("  Instances: %s" % ", ".join(cv.get("instance_names", [])))
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
    
    print("LATENCY STATISTICS (successful resolutions):")
    print("  Average: %d ms | Min: %d ms | Max: %d ms" % (lat["avg_ms"], lat["min_ms"], lat["max_ms"]))
    print("  P50: %d ms | P95: %d ms | P99: %d ms" % (lat["p50_ms"], lat["p95_ms"], lat["p99_ms"]))
    print()

    failures = report["failures"]
    if failures:
        print("FAILED RELAYS (%d):" % len(failures))
        for f in failures[:20]:
            print("  - %-20s (%s...) [%s] %s" % (
                f.get("exit_nickname", "unknown")[:20],
                f["exit_fingerprint"][:8],
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
    args = parser.parse_args()

    cv_stats = None
    
    if args.cross_validate and args.sources:
        # Cross-validation mode: merge best results from multiple sources
        results, cv_stats = cross_validate_results(args.sources)
        if not results:
            print("No results found in source directories")
            return 1
        print("Cross-validated %d unique relays from %d sources" % (len(results), len(args.sources)))
    else:
        # Standard mode: load from single input directory
        results = load_results(args.input)
        if not results:
            print("No results found in %s" % args.input)
            return 1
        print("Loaded %d results" % len(results))

    report = aggregate_results(results, args.previous)
    
    # Add cross-validation metadata if applicable
    if cv_stats:
        report["metadata"]["cross_validation"] = {
            "enabled": True,
            "instances": cv_stats["instances"],
            "instance_names": cv_stats.get("instance_names", []),
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
