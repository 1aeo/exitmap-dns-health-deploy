#!/usr/bin/env python3
"""
Safe log parser for exitmap output.
Extracts progress information without shell injection risks.

Usage:
    python3 parse_exitmap_log.py /path/to/log_file

Output (JSON):
    {"probed": 123, "total": 456, "pct": 27.0, "ok": 100, "timeout": 10, "failed": 5}
"""

import json
import re
import sys


def parse_exitmap_log(log_file):
    """
    Safely extract progress info from exitmap log file.
    
    Returns dict with:
        probed: Number of relays probed
        total: Total relays to probe
        pct: Percentage complete
        ok: Count of successful results
        timeout: Count of timeout results
        failed: Count of failed results
    """
    result = {
        "probed": 0,
        "total": 0,
        "pct": 0.0,
        "ok": 0,
        "timeout": 0,
        "failed": 0
    }
    
    # Patterns to match (compiled for efficiency)
    progress_pattern = re.compile(
        r'Probed\s+(\d+)\s+out\s+of\s+(\d+)\s+exit\s+relays.*?(\d+\.\d+)%\s+done'
    )
    
    try:
        with open(log_file, 'r', errors='replace') as f:
            for line in f:
                # Check for progress line
                match = progress_pattern.search(line)
                if match:
                    result["probed"] = int(match.group(1))
                    result["total"] = int(match.group(2))
                    result["pct"] = float(match.group(3))
                
                # Count result types (simple substring checks are safe)
                if '(correct)' in line:
                    result["ok"] += 1
                elif '[timeout]' in line:
                    result["timeout"] += 1
                elif '[FAILED]' in line:
                    result["failed"] += 1
    except FileNotFoundError:
        pass  # Return zeros if file doesn't exist
    except Exception:
        pass  # Return zeros on any other error
    
    return result


def main():
    if len(sys.argv) < 2:
        log_file = "/dev/null"
    else:
        log_file = sys.argv[1]
    
    result = parse_exitmap_log(log_file)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
