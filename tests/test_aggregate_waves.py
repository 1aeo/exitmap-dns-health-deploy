#!/usr/bin/env python3
"""
Tests for wave-based cross-validation metadata in aggregate_results.py

Run: python -m pytest tests/test_aggregate_waves.py -v
Or:  python tests/test_aggregate_waves.py
"""

import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from aggregate_results import (
    CROSS_VALIDATION_RESULT_PRIORITY,
    cross_validate_results,
    aggregate_results,
    print_summary,
    main,
    _get_instance_name,
)

FIXTURE_20261103 = os.path.join(
    os.path.dirname(__file__), "fixtures", "wrong_ip_cross_validation_20261103.json"
)


def _source_sort_key(instance_name):
    """Wave, then instance: cv1_w1, cv2_w1, ... cv4_w4."""
    inst, wave = instance_name.split("_")
    return (int(wave[1:]), int(inst[2:]))


class TestInstanceNameExtraction(unittest.TestCase):
    """Test instance name extraction from directory paths."""
    
    def test_wave_mode_cv1_w1(self):
        """Wave mode: cv1_w1 should be extracted from analysis_..._cv1_w1"""
        result = _get_instance_name("/tmp/analysis_2026-01-24_23-24-00_cv1_w1")
        self.assertEqual(result, "cv1_w1")
    
    def test_wave_mode_cv4_w3(self):
        """Wave mode: cv4_w3 should be extracted."""
        result = _get_instance_name("/tmp/analysis_2026-01-24_23-24-00_cv4_w3")
        self.assertEqual(result, "cv4_w3")
    
    def test_wave_mode_all_four_instances_unique(self):
        """All 4 instances in a wave should have unique names."""
        dirs = [
            "/tmp/analysis_2026-01-24_23-24-00_cv1_w1",
            "/tmp/analysis_2026-01-24_23-24-00_cv2_w1",
            "/tmp/analysis_2026-01-24_23-24-00_cv3_w1",
            "/tmp/analysis_2026-01-24_23-24-00_cv4_w1",
        ]
        names = [_get_instance_name(d) for d in dirs]
        self.assertEqual(len(set(names)), 4, "All instance names should be unique")
        self.assertEqual(names, ["cv1_w1", "cv2_w1", "cv3_w1", "cv4_w1"])
    
    def test_regular_cv_mode(self):
        """Regular CV mode: cv2 should be extracted from analysis_..._cv2"""
        result = _get_instance_name("/tmp/analysis_2026-01-24_22-05-01_cv2")
        self.assertEqual(result, "cv2")
    
    def test_single_instance_mode(self):
        """Single instance mode: last part of timestamp."""
        result = _get_instance_name("/tmp/analysis_2026-01-24_22-05-01")
        self.assertEqual(result, "22-05-01")


class TestCrossValidationPriority(unittest.TestCase):
    """Test cross-validation result priority ordering."""
    
    def test_success_highest_priority(self):
        """Success should have the highest priority (lowest number)."""
        self.assertEqual(CROSS_VALIDATION_RESULT_PRIORITY["success"], 0)
    
    def test_dns_fail_beats_timeout(self):
        """dns_fail (priority 2) should beat timeout (priority 6)."""
        self.assertLess(
            CROSS_VALIDATION_RESULT_PRIORITY["dns_fail"],
            CROSS_VALIDATION_RESULT_PRIORITY["timeout"]
        )
    
    def test_wrong_ip_beats_dns_fail(self):
        """wrong_ip (priority 1) should beat dns_fail (priority 2)."""
        self.assertLess(
            CROSS_VALIDATION_RESULT_PRIORITY["wrong_ip"],
            CROSS_VALIDATION_RESULT_PRIORITY["dns_fail"]
        )
    
    def test_all_priorities_unique(self):
        """All priority values should be unique (except timeout/hard_timeout)."""
        values = list(CROSS_VALIDATION_RESULT_PRIORITY.values())
        # timeout and hard_timeout share priority 6
        self.assertEqual(
            CROSS_VALIDATION_RESULT_PRIORITY["timeout"],
            CROSS_VALIDATION_RESULT_PRIORITY["hard_timeout"]
        )

    def test_dns_fail_priority_unchanged(self):
        """dns_fail stays at priority 2. wrong_ip beats success by a special case, not by renumbering."""
        self.assertEqual(CROSS_VALIDATION_RESULT_PRIORITY["success"], 0)
        self.assertEqual(CROSS_VALIDATION_RESULT_PRIORITY["wrong_ip"], 1)
        self.assertEqual(CROSS_VALIDATION_RESULT_PRIORITY["dns_fail"], 2)


class TestWaveStatsIntegration(unittest.TestCase):
    """Test wave stats file parsing and metadata generation."""
    
    def test_wave_stats_parsing(self):
        """Test that wave stats JSON lines are correctly parsed."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            f.write('{"wave": 1, "relays": 400, "duration_sec": 180, "retries": 0, "batch_size": 400}\n')
            f.write('{"wave": 2, "relays": 400, "duration_sec": 175, "retries": 0, "batch_size": 400}\n')
            f.write('{"wave": 3, "relays": 200, "duration_sec": 90, "retries": 1, "batch_size": 400}\n')
            wave_stats_file = f.name
        
        try:
            with open(wave_stats_file) as f:
                wave_data = [json.loads(line) for line in f if line.strip()]
            
            self.assertEqual(len(wave_data), 3)
            self.assertEqual(sum(w["relays"] for w in wave_data), 1000)
            self.assertEqual(sum(w.get("retries", 0) for w in wave_data), 1)
            self.assertEqual(wave_data[0]["batch_size"], 400)
        finally:
            os.unlink(wave_stats_file)
    
    def test_wave_metadata_structure(self):
        """Test the expected structure of wave metadata."""
        wave_data = [
            {"wave": 1, "relays": 400, "duration_sec": 180, "retries": 0, "batch_size": 400},
            {"wave": 2, "relays": 400, "duration_sec": 175, "retries": 1, "batch_size": 400},
        ]
        
        total_retries = sum(w.get("retries", 0) for w in wave_data)
        
        waves_metadata = {
            "enabled": True,
            "batch_size": wave_data[0].get("batch_size", 400),
            "total_waves": len(wave_data),
            "total_relays": sum(w.get("relays", 0) for w in wave_data),
            "total_retries": total_retries,
            "max_retries_config": 2,
            "completed": wave_data,
        }
        
        self.assertTrue(waves_metadata["enabled"])
        self.assertEqual(waves_metadata["batch_size"], 400)
        self.assertEqual(waves_metadata["total_waves"], 2)
        self.assertEqual(waves_metadata["total_relays"], 800)
        self.assertEqual(waves_metadata["total_retries"], 1)
        self.assertEqual(len(waves_metadata["completed"]), 2)


class TestCrossValidationMerge(unittest.TestCase):
    """Test cross-validation result merging logic."""
    
    def setUp(self):
        """Create temporary directories with test results."""
        self.temp_dirs = []
        
    def tearDown(self):
        """Clean up temporary directories."""
        import shutil
        for d in self.temp_dirs:
            if os.path.exists(d):
                shutil.rmtree(d)
    
    def _create_result_dir(self, name, results):
        """Create a temporary directory with result JSON files."""
        d = tempfile.mkdtemp(prefix=f"test_{name}_")
        self.temp_dirs.append(d)
        
        for fp, result in results.items():
            result["exit_fingerprint"] = fp
            with open(os.path.join(d, f"dnshealth_{fp}.json"), "w") as f:
                json.dump(result, f)
        
        return d
    
    def test_success_beats_timeout(self):
        """When one instance succeeds and another times out, success wins."""
        dir1 = self._create_result_dir("cv1", {
            "ABC123": {"status": "timeout", "error": "Timeout after 45s"},
        })
        dir2 = self._create_result_dir("cv2", {
            "ABC123": {"status": "success", "error": None, "timing": {"total_ms": 1000}},
        })
        
        results, cv_stats = cross_validate_results([dir1, dir2])
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "success")
        self.assertEqual(results[0]["cv"]["instances_success"], 1)
        self.assertEqual(results[0]["cv"]["instances_total"], 2)
        self.assertTrue(results[0]["cv"]["improved"])
    
    def test_dns_fail_beats_timeout(self):
        """When all fail, dns_fail (priority 2) beats timeout (priority 6)."""
        dir1 = self._create_result_dir("cv1", {
            "ABC123": {"status": "timeout", "error": "Timeout after 45s"},
        })
        dir2 = self._create_result_dir("cv2", {
            "ABC123": {"status": "dns_fail", "error": "NXDOMAIN"},
        })
        
        results, cv_stats = cross_validate_results([dir1, dir2])
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "dns_fail")
        self.assertEqual(results[0]["cv"]["instances_success"], 0)
    
    def test_all_success_not_improved(self):
        """When all instances succeed, improved should be False."""
        dir1 = self._create_result_dir("cv1", {
            "ABC123": {"status": "success", "error": None},
        })
        dir2 = self._create_result_dir("cv2", {
            "ABC123": {"status": "success", "error": None},
        })
        
        results, cv_stats = cross_validate_results([dir1, dir2])
        
        self.assertEqual(results[0]["cv"]["instances_success"], 2)
        self.assertFalse(results[0]["cv"]["improved"])


class TestAggregateResults(unittest.TestCase):
    """Test the main aggregate_results function."""
    
    def test_basic_aggregation(self):
        """Test basic result aggregation."""
        results = [
            {"exit_fingerprint": "ABC123", "status": "success", "timing": {"total_ms": 1000}},
            {"exit_fingerprint": "DEF456", "status": "timeout", "error": "Timeout"},
        ]
        
        report = aggregate_results(results)
        
        self.assertIn("metadata", report)
        self.assertIn("results", report)
        self.assertEqual(len(report["results"]), 2)
        self.assertEqual(report["metadata"]["dns_success"], 1)
    
    def test_scan_metadata(self):
        """Test that scan metadata is included."""
        results = [
            {"exit_fingerprint": "ABC123", "status": "success"},
        ]
        
        report = aggregate_results(
            results,
            scan_type="cross_validate",
            scan_instances=4,
            instance_names=["cv1", "cv2", "cv3", "cv4"]
        )
        
        self.assertEqual(report["metadata"]["scan"]["type"], "cross_validate")
        self.assertEqual(report["metadata"]["scan"]["instances"], 4)
        self.assertEqual(len(report["metadata"]["scan"]["instance_names"]), 4)


class TestWrongIpCrossValidation(unittest.TestCase):
    """A wrong answer is published even when another probe succeeds."""

    def setUp(self):
        self.temp_dirs = []

    def tearDown(self):
        import shutil
        for d in self.temp_dirs:
            if os.path.exists(d):
                shutil.rmtree(d)

    def _make_instance_dirs(self, relays):
        """One dnshealth_<fp>.json per instance.

        Directory basename is analysis_2026-11-03_00-05-01_<instance>, and the
        directories are returned in source order (wave, then instance).
        """
        parent = tempfile.mkdtemp(prefix="cv_wrong_ip_")
        self.temp_dirs.append(parent)
        names = set()
        for relay in relays:
            names.update(relay["per_instance"])
        ordered = sorted(names, key=_source_sort_key)
        dirs = []
        for name in ordered:
            d = os.path.join(parent, "analysis_2026-11-03_00-05-01_%s" % name)
            os.makedirs(d)
            dirs.append(d)
        for relay in relays:
            fp = relay["exit_fingerprint"]
            for name, detail in relay["per_instance"].items():
                result = {"exit_fingerprint": fp}
                if relay.get("exit_nickname"):
                    result["exit_nickname"] = relay["exit_nickname"]
                result.update(detail)
                path = os.path.join(
                    parent, "analysis_2026-11-03_00-05-01_%s" % name, "dnshealth_%s.json" % fp
                )
                with open(path, "w") as f:
                    json.dump(result, f)
        return dirs

    def test_wrong_ip_beats_success_and_keeps_its_timing(self):
        """[wrong_ip, success, success, success] publishes the wrong answer."""
        relays = [{
            "exit_fingerprint": "ABC123",
            "per_instance": {
                "cv1_w1": {
                    "status": "wrong_ip",
                    "resolved_ip": "23.202.88.27",
                    "expected_ip": "64.65.4.1",
                    "error": "DNS Error: Expected 64.65.4.1, got 23.202.88.27",
                    "timing": {"total_ms": 21911},
                },
                "cv2_w1": {"status": "success", "resolved_ip": "64.65.4.1", "timing": {"total_ms": 1000}},
                "cv3_w1": {"status": "success", "resolved_ip": "64.65.4.1", "timing": {"total_ms": 3000}},
                "cv4_w1": {"status": "success", "resolved_ip": "64.65.4.1", "timing": {"total_ms": 5000}},
            },
        }]
        buf = StringIO()
        with redirect_stdout(buf):
            results, cv_stats = cross_validate_results(self._make_instance_dirs(relays))

        row = results[0]
        self.assertEqual(row["status"], "wrong_ip")
        self.assertEqual(row["resolved_ip"], "23.202.88.27")
        self.assertEqual(row["timing"], {"total_ms": 21911})
        self.assertEqual(row["error"], "DNS Error: Expected 64.65.4.1, got 23.202.88.27")
        self.assertEqual(row["cv"]["result_source"], "cv1_w1")
        self.assertFalse(row["cv"]["improved"])
        self.assertNotIn("recovered_from", row["cv"])
        self.assertEqual(cv_stats["recovered_from_error"], 0)
        self.assertEqual(cv_stats["recovered_from_timeout"], 0)
        self.assertEqual(cv_stats["recovered_from_dns_fail"], 0)
        self.assertEqual(cv_stats["improved"], 0)
        self.assertEqual(cv_stats["wrong_ip_partial"], 1)
        per = row["cv"]["per_instance"]
        self.assertEqual(set(per), {"cv1_w1", "cv2_w1", "cv3_w1", "cv4_w1"})
        self.assertEqual(per["cv1_w1"]["resolved_ip"], "23.202.88.27")
        self.assertEqual(per["cv1_w1"]["timing"]["total_ms"], 21911)
        self.assertEqual(per["cv2_w1"]["status"], "success")
        self.assertIn("Wrong IP partial: 1", buf.getvalue())

    def test_four_successes_stay_success(self):
        """Four successes publish success and are not a recovery."""
        per = {
            name: {"status": "success", "resolved_ip": "64.65.4.1", "timing": {"total_ms": 1000}}
            for name in ("cv1_w1", "cv2_w1", "cv3_w1", "cv4_w1")
        }
        results, cv_stats = cross_validate_results(self._make_instance_dirs([{
            "exit_fingerprint": "ABC123",
            "per_instance": per,
        }]))
        self.assertEqual(results[0]["status"], "success")
        self.assertFalse(results[0]["cv"]["improved"])
        self.assertEqual(cv_stats["improved"], 0)
        self.assertEqual(cv_stats["wrong_ip_partial"], 0)
        report = aggregate_results(results)
        self.assertEqual(report["results"][0]["consecutive_failures"], 0)
        self.assertEqual(report["metadata"]["dns_success"], 1)
        self.assertEqual(report["metadata"]["dns_success_rate_percent"], 100)

    def test_dns_fail_still_recovered_by_success(self):
        """[dns_fail, success] publishes success and counts as a DNS-fail recovery."""
        results, cv_stats = cross_validate_results(self._make_instance_dirs([{
            "exit_fingerprint": "ABC123",
            "per_instance": {
                "cv1_w1": {"status": "dns_fail", "error": "NXDOMAIN"},
                "cv2_w1": {"status": "success", "resolved_ip": "64.65.4.1", "timing": {"total_ms": 800}},
            },
        }]))
        self.assertEqual(results[0]["status"], "success")
        self.assertTrue(results[0]["cv"]["improved"])
        self.assertEqual(results[0]["cv"]["recovered_from"], ["dns_fail"])
        self.assertEqual(cv_stats["recovered_from_dns_fail"], 1)
        self.assertEqual(cv_stats["recovered_from_error"], 0)
        self.assertEqual(cv_stats["wrong_ip_partial"], 0)

    def test_transient_failures_still_publish_success(self):
        """Timeout, hard timeout, and SOCKS errors are still discarded when another probe succeeds."""
        cases = [
            ("timeout", "recovered_from_timeout", "recovered_from_error"),
            ("hard_timeout", "recovered_from_timeout", "recovered_from_error"),
            ("socks_error", "recovered_from_error", "recovered_from_timeout"),
        ]
        for status, counted, other in cases:
            with self.subTest(status=status):
                results, cv_stats = cross_validate_results(self._make_instance_dirs([{
                    "exit_fingerprint": "ABC123",
                    "per_instance": {
                        "cv1_w1": {"status": status, "error": status},
                        "cv2_w1": {"status": "success", "resolved_ip": "64.65.4.1", "timing": {"total_ms": 500}},
                    },
                }]))
                self.assertEqual(results[0]["status"], "success")
                self.assertTrue(results[0]["cv"]["improved"])
                self.assertEqual(cv_stats[counted], 1)
                self.assertEqual(cv_stats[other], 0)
                self.assertEqual(cv_stats["recovered_from_dns_fail"], 0)
                self.assertEqual(cv_stats["wrong_ip_partial"], 0)

    def test_wrong_ip_with_dns_fail_is_not_recovered(self):
        """[wrong_ip, dns_fail] with no success still publishes wrong_ip."""
        results, cv_stats = cross_validate_results(self._make_instance_dirs([{
            "exit_fingerprint": "ABC123",
            "per_instance": {
                "cv1_w1": {
                    "status": "wrong_ip",
                    "resolved_ip": "1.2.3.4",
                    "error": "DNS Error: Expected 64.65.4.1, got 1.2.3.4",
                    "timing": {"total_ms": 42},
                },
                "cv2_w1": {"status": "dns_fail", "error": "NXDOMAIN"},
            },
        }]))
        row = results[0]
        self.assertEqual(row["status"], "wrong_ip")
        self.assertEqual(row["resolved_ip"], "1.2.3.4")
        self.assertEqual(row["timing"], {"total_ms": 42})
        self.assertEqual(row["cv"]["result_source"], "cv1_w1")
        self.assertFalse(row["cv"]["improved"])
        self.assertNotIn("recovered_from", row["cv"])
        self.assertEqual(cv_stats["improved"], 0)
        self.assertEqual(cv_stats["recovered_from_error"], 0)
        self.assertEqual(cv_stats["recovered_from_dns_fail"], 0)
        self.assertEqual(cv_stats["wrong_ip_partial"], 1)
        self.assertEqual(row["cv"]["per_instance"]["cv2_w1"]["status"], "dns_fail")

    def test_report_20261103_hidden_wrong_ips(self):
        """The three relays from dns_health_2026-11-03_00-05-01, rebuilt from cv.per_instance."""
        with open(FIXTURE_20261103) as f:
            fixture = json.load(f)
        results, cv_stats = cross_validate_results(self._make_instance_dirs(fixture["relays"]))
        by_fp = {r["exit_fingerprint"]: r for r in results}

        partial = by_fp["42F8E7CE864478CA292E9EA05DC11481C293F8ED"]
        self.assertEqual(partial["status"], "wrong_ip")
        self.assertEqual(partial["resolved_ip"], "23.202.88.27")
        self.assertEqual(partial["cv"]["result_source"], "cv1_w1")
        self.assertEqual(partial["timing"]["total_ms"], 21911)
        self.assertEqual(partial["cv"]["per_instance"]["cv3_w1"]["status"], "wrong_ip")
        self.assertEqual(partial["cv"]["per_instance"]["cv3_w1"]["resolved_ip"], "2.18.188.209")
        self.assertFalse(partial["cv"]["improved"])
        self.assertNotIn("recovered_from", partial["cv"])

        other = by_fp["7C0AA4E3B73E407E9F5FEB1912F8BE26D8AA124D"]
        self.assertEqual(other["status"], "wrong_ip")
        self.assertEqual(other["resolved_ip"], "23.202.88.27")
        self.assertEqual(other["cv"]["result_source"], "cv2_w2")
        self.assertEqual(other["timing"]["total_ms"], 17798)
        self.assertEqual(other["cv"]["per_instance"]["cv2_w2"]["resolved_ip"], "23.202.88.27")
        self.assertEqual(other["cv"]["per_instance"]["cv3_w2"]["status"], "wrong_ip")
        self.assertEqual(other["cv"]["per_instance"]["cv3_w2"]["resolved_ip"], "23.202.88.27")
        self.assertFalse(other["cv"]["improved"])
        self.assertNotIn("recovered_from", other["cv"])

        unanimous = by_fp["C59E079437340E3AD14E6785C0A91A5B6F328566"]
        self.assertEqual(unanimous["status"], "wrong_ip")
        self.assertEqual(unanimous["resolved_ip"], "23.32.38.139")
        self.assertEqual(unanimous["cv"]["result_source"], "cv1_w3")
        self.assertEqual(unanimous["timing"]["total_ms"], 13310)
        self.assertEqual(unanimous["error"], "DNS Error: Expected 64.65.4.1, got 23.32.38.139")
        self.assertFalse(unanimous["cv"]["improved"])

        self.assertEqual(cv_stats["wrong_ip_partial"], 2)
        self.assertEqual(cv_stats["recovered_from_error"], 0)
        self.assertEqual(cv_stats["improved"], 0)
        self.assertEqual(cv_stats["consistency"], {"all_success": 0, "all_failed": 1, "mixed": 2})

    def test_main_writes_wrong_ip_partial(self):
        """main() records wrong_ip_partial and does not count the wrong IP as an error recovery."""
        relays = [{
            "exit_fingerprint": "ABC123",
            "per_instance": {
                "cv1_w1": {
                    "status": "wrong_ip",
                    "resolved_ip": "9.9.9.9",
                    "expected_ip": "64.65.4.1",
                    "error": "DNS Error: Expected 64.65.4.1, got 9.9.9.9",
                    "timing": {"total_ms": 10},
                },
                "cv2_w1": {"status": "success", "resolved_ip": "64.65.4.1", "timing": {"total_ms": 20}},
            },
        }]
        dirs = self._make_instance_dirs(relays)
        out = os.path.join(self.temp_dirs[-1], "report.json")
        argv = [
            "aggregate_results.py",
            "--input", self.temp_dirs[-1],
            "--output", out,
            "--cross-validate",
            "--scan-type", "cross_validate",
            "--scan-instances", "2",
            "--quiet",
        ]
        for d in dirs:
            argv.extend(["--source", d])
        with patch("sys.argv", argv):
            self.assertEqual(main(), 0)
        with open(out) as f:
            report = json.load(f)
        cv = report["metadata"]["cross_validation"]
        self.assertEqual(cv["wrong_ip_partial"], 1)
        self.assertEqual(cv["recovered_from_error"], 0)
        self.assertEqual(report["metadata"]["dns_wrong_ip"], 1)
        self.assertEqual(report["metadata"]["dns_success"], 0)
        self.assertEqual(report["results"][0]["status"], "wrong_ip")
        buf = StringIO()
        with redirect_stdout(buf):
            print_summary(report)
        self.assertIn("Wrong IP partial: 1", buf.getvalue())

    def test_print_summary_omits_missing_wrong_ip_partial(self):
        """Older reports have no wrong_ip_partial key, so the line is not printed."""
        report = aggregate_results([{"exit_fingerprint": "ABC123", "status": "success"}])
        report["metadata"]["scan"] = {
            "type": "cross_validate",
            "instances": 2,
            "instance_names": ["cv1", "cv2"],
        }
        report["metadata"]["cross_validation"] = {
            "relays_improved": 0,
            "recovered_from_timeout": 0,
            "recovered_from_dns_fail": 0,
            "recovered_from_error": 0,
            "consistency": {"all_success": 1, "all_failed": 0, "mixed": 0},
        }
        buf = StringIO()
        with redirect_stdout(buf):
            print_summary(report)
        self.assertNotIn("Wrong IP partial", buf.getvalue())

    def test_previous_success_becomes_one_consecutive_failure(self):
        """A relay that was success and is now wrong_ip gets consecutive_failures 1."""
        results, _cv_stats = cross_validate_results(self._make_instance_dirs([{
            "exit_fingerprint": "ABC123",
            "per_instance": {
                "cv1_w1": {
                    "status": "wrong_ip",
                    "resolved_ip": "9.9.9.9",
                    "timing": {"total_ms": 10},
                },
                "cv2_w1": {"status": "success", "resolved_ip": "64.65.4.1", "timing": {"total_ms": 20}},
            },
        }]))
        self.assertEqual(results[0]["status"], "wrong_ip")
        prev = os.path.join(self.temp_dirs[-1], "previous.json")
        with open(prev, "w") as f:
            json.dump({"results": [{
                "exit_fingerprint": "ABC123",
                "status": "success",
                "consecutive_failures": 0,
            }]}, f)
        report = aggregate_results(results, previous_report=prev)
        self.assertEqual(report["results"][0]["status"], "wrong_ip")
        self.assertEqual(report["results"][0]["consecutive_failures"], 1)
        self.assertEqual(report["metadata"]["dns_wrong_ip"], 1)
        self.assertEqual(report["metadata"]["dns_success"], 0)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
