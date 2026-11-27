#!/usr/bin/env python3
"""
Tests for status prioritization, metadata roll-up, circuit normalization,
and runner/UI compatibility with exitmap dnshealth statuses.
"""

import json
import os
import re
import shutil
import tempfile
import unittest

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from aggregate_results import (  # noqa: E402
    CROSS_VALIDATION_RESULT_PRIORITY,
    STATUS_TO_DNS_METADATA_KEY,
    _normalize_circuit_reason,
    aggregate_results,
    cross_validate_results,
)

DNS_METADATA_KEYS = (
    "dns_success",
    "dns_fail",
    "dns_timeout",
    "dns_wrong_ip",
    "dns_socks_error",
    "dns_network_error",
    "dns_error",
    "dns_exception",
    "dns_unknown",
)

EMITTED_DNSHEALTH_TESTED_STATUSES = (
    "success",
    "wrong_ip",
    "dns_fail",
    "socks_general_failure",
    "socks_ruleset_blocked",
    "network_unreachable",
    "connection_refused",
    "ttl_expired",
    "socks_command_unsupported",
    "socks_address_unsupported",
    "socks_error",
    "timeout",
    "hard_timeout",
    "eof_error",
    "tor_connection_lost",
    "tor_connection_refused",
    "exception",
    "unknown",
)


class TestPriorityCoverage(unittest.TestCase):
    """All emitted dnshealth statuses must be explicitly prioritized."""

    def test_all_emitted_statuses_beat_relay_unreachable(self):
        unreachable_prio = CROSS_VALIDATION_RESULT_PRIORITY["relay_unreachable"]
        self.assertEqual(unreachable_prio, 9)
        for status in EMITTED_DNSHEALTH_TESTED_STATUSES:
            with self.subTest(status=status):
                self.assertIn(status, CROSS_VALIDATION_RESULT_PRIORITY)
                self.assertLess(CROSS_VALIDATION_RESULT_PRIORITY[status], unreachable_prio)

    def test_real_relay_errors_beat_scanner_and_unreachable_in_cv(self):
        temp_dirs = []
        try:
            def make_dir(name, fp, status, error):
                d = tempfile.mkdtemp(prefix=f"test_{name}_")
                temp_dirs.append(d)
                with open(os.path.join(d, f"dnshealth_{fp}.json"), "w") as f:
                    json.dump({
                        "exit_fingerprint": fp,
                        "status": status,
                        "error": error,
                    }, f)
                return d

            d1 = make_dir("cv1", "FP_RELAY_WIN", "tor_connection_lost", "Exitmap Error: Lost connection")
            d2 = make_dir("cv2", "FP_RELAY_WIN", "socks_general_failure", "Tor Error: SOCKS 1")
            results, _ = cross_validate_results([d1, d2])
            self.assertEqual(results[0]["status"], "socks_general_failure")

            d3 = make_dir("cv3", "FP_SCANNER_WIN", "relay_unreachable", "Tor Circuit: Timeout")
            d4 = make_dir("cv4", "FP_SCANNER_WIN", "tor_connection_refused", "Exitmap Error: Refused")
            results2, _ = cross_validate_results([d3, d4])
            self.assertEqual(results2[0]["status"], "tor_connection_refused")
        finally:
            for d in temp_dirs:
                if os.path.exists(d):
                    shutil.rmtree(d)


class TestMetadataRollup(unittest.TestCase):
    """All tested statuses should roll cleanly into the 9 existing dns_* metadata keys."""

    def test_emitted_statuses_roll_up_and_reconcile_with_tested_relays(self):
        results = [
            {"exit_fingerprint": "A" * 40, "status": "success", "timing": {"total_ms": 100}},
            {"exit_fingerprint": "B" * 40, "status": "wrong_ip"},
            {"exit_fingerprint": "C" * 40, "status": "dns_fail"},
            {"exit_fingerprint": "D" * 40, "status": "timeout"},
            {"exit_fingerprint": "E" * 40, "status": "hard_timeout"},
            {"exit_fingerprint": "F" * 40, "status": "ttl_expired"},
            {"exit_fingerprint": "G" * 40, "status": "socks_error"},
            {"exit_fingerprint": "H" * 40, "status": "socks_general_failure"},
            {"exit_fingerprint": "I" * 40, "status": "socks_ruleset_blocked"},
            {"exit_fingerprint": "J" * 40, "status": "connection_refused"},
            {"exit_fingerprint": "K" * 40, "status": "socks_command_unsupported"},
            {"exit_fingerprint": "L" * 40, "status": "socks_address_unsupported"},
            {"exit_fingerprint": "M" * 40, "status": "network_unreachable"},
            {"exit_fingerprint": "N" * 40, "status": "eof_error"},
            {"exit_fingerprint": "O" * 40, "status": "tor_connection_lost"},
            {"exit_fingerprint": "P" * 40, "status": "tor_connection_refused"},
            {"exit_fingerprint": "Q" * 40, "status": "exception"},
            {"exit_fingerprint": "R" * 40, "status": "unrecognized_future_status"},
            {"exit_fingerprint": "S" * 40, "status": "relay_unreachable"},
        ]

        report = aggregate_results(results)
        meta = report["metadata"]

        self.assertEqual(meta["dns_success"], 1)
        self.assertEqual(meta["dns_wrong_ip"], 1)
        self.assertEqual(meta["dns_fail"], 1)
        self.assertEqual(meta["dns_timeout"], 3)        # timeout, hard_timeout, ttl_expired
        self.assertEqual(meta["dns_socks_error"], 6)    # socks_error + 5 specific SOCKS statuses
        self.assertEqual(meta["dns_network_error"], 1)  # network_unreachable
        self.assertEqual(meta["dns_error"], 3)          # eof_error, tor_connection_lost, tor_connection_refused
        self.assertEqual(meta["dns_exception"], 1)
        self.assertEqual(meta["dns_unknown"], 1)        # unrecognized_future_status
        self.assertEqual(meta["unreachable_relays"], 1)
        self.assertEqual(meta["tested_relays"], 18)
        self.assertEqual(
            meta["tested_relays"],
            sum(meta[k] for k in DNS_METADATA_KEYS),
        )
        self.assertEqual(set(STATUS_TO_DNS_METADATA_KEY.values()), set(DNS_METADATA_KEYS))

    def test_circuit_creation_failed_normalized(self):
        self.assertEqual(_normalize_circuit_reason("circuit_creation_failed"), "circuit_failed")


class TestRunnerAndCssCompatibility(unittest.TestCase):
    """Runner script env exports and badge styling should cover updated exitmap behavior."""

    def test_runner_exports_tor_bootstrap_timeout(self):
        script = (REPO_ROOT / "scripts" / "run-dns-validation.sh").read_text(encoding="utf-8")
        self.assertRegex(script, re.compile(r'(?m)^export TOR_BOOTSTRAP_TIMEOUT="\$\{TOR_BOOTSTRAP_TIMEOUT:-90\}"$'))
        self.assertNotIn("export EXITMAP_GRACE_TIMEOUT", script)

    def test_index_html_has_styles_for_emitted_statuses(self):
        html = (REPO_ROOT / "public" / "index.html").read_text(encoding="utf-8")
        for status in (
            "ttl_expired",
            "network_unreachable",
            "socks_general_failure",
            "socks_ruleset_blocked",
            "connection_refused",
            "socks_command_unsupported",
            "socks_address_unsupported",
            "eof_error",
            "tor_connection_lost",
            "tor_connection_refused",
        ):
            with self.subTest(status=status):
                self.assertIn(f".status-chip.{status}", html)
                self.assertIn(f".status-badge.{status}", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
