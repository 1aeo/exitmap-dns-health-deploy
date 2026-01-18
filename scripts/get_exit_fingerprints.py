#!/usr/bin/env python3
"""
Extract exit relay fingerprints from a Tor data directory.
Used by split mode to divide relays among multiple instances.
"""

import argparse
import sys
import os

# Add src to path for relayselector
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import stem.descriptor


def get_exit_fingerprints(data_dir, good_exit=True, bad_exit=False):
    """Get all exit relay fingerprints from the cached consensus."""
    
    # Try both consensus file names (depends on Tor configuration)
    cached_consensus_path = os.path.join(data_dir, "cached-consensus")
    if not os.path.exists(cached_consensus_path):
        cached_consensus_path = os.path.join(data_dir, "cached-microdesc-consensus")
    
    if not os.path.exists(cached_consensus_path):
        print(f"Error: No consensus file found in {data_dir}", file=sys.stderr)
        print(f"Looked for: cached-consensus, cached-microdesc-consensus", file=sys.stderr)
        sys.exit(1)
    
    # Get relays with EXIT flag
    have_exit_flag = set()
    for desc in stem.descriptor.parse_file(cached_consensus_path):
        if stem.Flag.EXIT in desc.flags:
            if bad_exit and good_exit:
                have_exit_flag.add(desc.fingerprint)
            elif bad_exit and stem.Flag.BADEXIT in desc.flags:
                have_exit_flag.add(desc.fingerprint)
            elif good_exit and stem.Flag.BADEXIT not in desc.flags:
                have_exit_flag.add(desc.fingerprint)
    
    return sorted(have_exit_flag)


def write_fingerprints(fingerprints, output_file):
    """Write fingerprints to a file, one per line."""
    with open(output_file, 'w') as f:
        for fp in fingerprints:
            f.write(f"{fp}\n")
    print(f"Wrote {len(fingerprints)} fingerprints to {output_file}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Extract exit relay fingerprints")
    parser.add_argument("data_dir", help="Tor data directory")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("-b", "--bad-exits", action="store_true",
                        help="Include bad exits")
    parser.add_argument("-a", "--all-exits", action="store_true",
                        help="Include all exits (good and bad)")
    parser.add_argument("--split", type=int, default=1,
                        help="Split into N files (adds .N suffix)")
    args = parser.parse_args()
    
    good_exit = True
    bad_exit = args.bad_exits or args.all_exits
    
    fingerprints = get_exit_fingerprints(args.data_dir, good_exit, bad_exit)
    
    if not fingerprints:
        print("Error: No exit relays found", file=sys.stderr)
        sys.exit(1)
    
    if args.split > 1:
        # Split fingerprints among N files
        if not args.output:
            print("Error: --output required when using --split", file=sys.stderr)
            sys.exit(1)
        
        # Distribute fingerprints round-robin
        splits = [[] for _ in range(args.split)]
        for i, fp in enumerate(fingerprints):
            splits[i % args.split].append(fp)
        
        for i, split_fps in enumerate(splits):
            write_fingerprints(split_fps, f"{args.output}.{i+1}")
    elif args.output:
        write_fingerprints(fingerprints, args.output)
    else:
        for fp in fingerprints:
            print(fp)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
