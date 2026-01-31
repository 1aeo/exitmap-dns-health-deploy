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

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from aggregate_results import (
    CROSS_VALIDATION_RESULT_PRIORITY,
    cross_validate_results,
    aggregate_results,
    _get_instance_name,
)


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


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
