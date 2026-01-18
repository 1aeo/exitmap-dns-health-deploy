#!/usr/bin/env python3
"""
Quick analysis of DNS Health scan results.
Usage: ./quick_analysis.py [results_dir] [--compare] [--failures] [--json]

For full aggregation, use aggregate_results.py instead.
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Import shared helpers from aggregate_results
try:
    from aggregate_results import _load_json_file, _iter_result_files
except ImportError:
    # Fallback if run standalone
    def _load_json_file(fpath):
        try:
            with open(fpath) as f:
                return json.load(f)
        except Exception:
            return None
    
    def _iter_result_files(directory, recursive=False):
        import os
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


def load_results(results_dir: Path) -> list:
    """Load all JSON results from a scan directory."""
    # Find dnshealth subdirectory
    dnshealth_dirs = list(results_dir.glob("*dnshealth*"))
    search_dir = str(dnshealth_dirs[0]) if dnshealth_dirs else str(results_dir)
    
    results = []
    for fpath in _iter_result_files(search_dir, recursive=True):
        result = _load_json_file(fpath)
        if result:
            results.append(result)
    return results


def compute_latency_stats(latencies: list) -> dict:
    """Compute latency statistics from a list of latency values."""
    if not latencies:
        return {}
    latencies = sorted(latencies)
    n = len(latencies)
    return {
        "min": latencies[0],
        "median": latencies[n // 2],
        "p95": latencies[int(n * 0.95)],
        "max": latencies[-1],
        "avg": sum(latencies) // n
    }


def analyze_results(results: list) -> dict:
    """Analyze results and return statistics."""
    if not results:
        return {}
    
    total = len(results)
    status_counts = Counter(r.get("status") for r in results)
    success = status_counts.get("success", 0)
    timeout = status_counts.get("timeout", 0)
    dns_fail = status_counts.get("dns_fail", 0)
    
    # Latency stats for successes
    latencies = [r.get("latency_ms") for r in results 
                 if r.get("status") == "success" and r.get("latency_ms")]
    
    return {
        "total": total,
        "success": success,
        "timeout": timeout,
        "dns_fail": dns_fail,
        "success_rate": round(success / total * 100, 2) if total else 0,
        "timeout_rate": round(timeout / total * 100, 2) if total else 0,
        "failures": total - success,
        "status_breakdown": dict(status_counts),
        "latency_stats": compute_latency_stats(latencies)
    }


def analyze_failures(results: list) -> dict:
    """Analyze failure patterns."""
    failures = [r for r in results if r.get("status") != "success"]
    
    # Group by status
    by_status = defaultdict(list)
    for r in failures:
        by_status[r.get("status")].append(r)
    
    # Group by IP address (identify problematic operators)
    by_ip = defaultdict(list)
    for r in failures:
        ip = r.get("exit_address", "unknown")
        by_ip[ip].append(r)
    
    # Top failing IPs
    top_ips = sorted(by_ip.items(), key=lambda x: -len(x[1]))[:20]
    
    return {
        "total_failures": len(failures),
        "by_status": {k: len(v) for k, v in by_status.items()},
        "top_failing_ips": [
            {"ip": ip, "count": len(relays), "fingerprints": [r.get("exit_fingerprint") for r in relays[:5]]}
            for ip, relays in top_ips
        ]
    }


def print_summary(stats: dict, run_name: str = ""):
    """Print human-readable summary."""
    print("=" * 70)
    print(f"DNS HEALTH SCAN RESULTS{' - ' + run_name if run_name else ''}")
    print("=" * 70)
    print(f"\nTotal relays tested: {stats['total']}")
    print(f"\nStatus breakdown:")
    for status, count in sorted(stats['status_breakdown'].items(), key=lambda x: -x[1]):
        pct = count / stats['total'] * 100 if stats['total'] else 0
        print(f"  {status:<20}: {count:>5} ({pct:>5.1f}%)")
    
    print(f"\nSuccess Rate: {stats['success_rate']:.1f}%")
    print(f"Total Failures: {stats['failures']}")
    
    if stats.get('latency_stats'):
        ls = stats['latency_stats']
        print(f"\nLatency (successful queries):")
        print(f"  Min:    {ls['min']:>6} ms")
        print(f"  Median: {ls['median']:>6} ms")
        print(f"  P95:    {ls['p95']:>6} ms")
        print(f"  Max:    {ls['max']:>6} ms")


def print_failures(failure_analysis: dict):
    """Print failure analysis."""
    print("\n" + "=" * 70)
    print("FAILURE ANALYSIS")
    print("=" * 70)
    print(f"\nTotal failures: {failure_analysis['total_failures']}")
    print(f"\nBy status:")
    for status, count in failure_analysis['by_status'].items():
        print(f"  {status}: {count}")
    
    print(f"\nTop failing IP addresses:")
    for item in failure_analysis['top_failing_ips'][:10]:
        print(f"  {item['ip']}: {item['count']} relays")


def compare_runs(results_dirs: list):
    """Compare multiple scan runs."""
    print("=" * 80)
    print("COMPARISON OF SCAN RUNS")
    print("=" * 80)
    print(f"\n{'Run':<30} {'Total':<8} {'Success':<10} {'Timeout':<10} {'Failures':<10}")
    print("-" * 80)
    
    for results_dir in results_dirs:
        results = load_results(results_dir)
        if not results:
            continue
        stats = analyze_results(results)
        name = results_dir.name[:28]
        print(f"{name:<30} {stats['total']:<8} {stats['success_rate']:.1f}%      {stats['timeout_rate']:.1f}%      {stats['failures']}")


def main():
    parser = argparse.ArgumentParser(description="Analyze DNS Health scan results")
    parser.add_argument("results_dir", nargs="?", default=".", 
                        help="Path to results directory")
    parser.add_argument("--compare", action="store_true",
                        help="Compare multiple runs (pass parent directory)")
    parser.add_argument("--failures", action="store_true",
                        help="Show detailed failure analysis")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    
    args = parser.parse_args()
    results_dir = Path(args.results_dir)
    
    if args.compare:
        # Compare all subdirectories
        subdirs = sorted([d for d in results_dir.iterdir() if d.is_dir()])
        compare_runs(subdirs)
        return
    
    results = load_results(results_dir)
    if not results:
        print(f"No results found in {results_dir}", file=sys.stderr)
        sys.exit(1)
    
    stats = analyze_results(results)
    
    if args.json:
        output = {"stats": stats}
        if args.failures:
            output["failures"] = analyze_failures(results)
        print(json.dumps(output, indent=2))
    else:
        print_summary(stats, results_dir.name)
        if args.failures:
            print_failures(analyze_failures(results))


if __name__ == "__main__":
    main()
