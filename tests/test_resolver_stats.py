#!/usr/bin/env python3
"""
Tests for scripts/resolver_stats.py (sampled DNS analytics -> per-exit resolver estimates)

Run: python -m pytest tests/test_resolver_stats.py -v
Or:  python tests/test_resolver_stats.py
"""

import io
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import resolver_stats
from resolver_stats import add_resolver_stats, asn_provider, graphql_rows, load_previous

FP_A, FP_B, FP_C, FP_D = ("AAAAAAAA" + "1" * 32, "BBBBBBBB" + "2" * 32,
                          "CCCCCCCC" + "3" * 32, "DDDDDDDD" + "4" * 32)
PROVIDERS = {"8.8.8.8": "google", "2001:4860::1": "google", "192.0.2.10": "other",
             "172.64.0.1": "cloudflare", "1.1.1.1": "cloudflare"}


def row(name, ip, sample=10):
    return {"datetime": "2026-10-11T19:10:00Z", "queryName": name, "sourceIP": ip, "sampleInterval": sample}


def make_report(timestamp="2026-10-11T19:26:08.878754Z"):
    return {"metadata": {"timestamp": timestamp}, "results": [
        {"exit_fingerprint": FP_A, "status": "success", "timestamp": 1791745519.8},
        {"exit_fingerprint": FP_B, "status": "success", "timestamp": 1791746524.9},
        {"exit_fingerprint": FP_C, "status": "timeout", "timestamp": 1791746000.0},
        {"exit_fingerprint": FP_D, "status": "success", "timestamp": 1791746100.0},
    ]}


ROWS = [
    row("u1.aaaaaaaa.tor.exit.validator.1aeo.com", "8.8.8.8"),
    row("u1.aaaaaaaa.tor.exit.validator.1aeo.com", "8.8.8.8"),
    row("aaaaaaaa.tor.exit.validator.1aeo.com", "2001:4860::1"),    # qname-minimised
    row("U2.AAAAAAAA.Tor.Exit.Validator.1aeo.com.", "192.0.2.10"),  # mixed case, trailing dot
    row("u3.bbbbbbbb.tor.exit.validator.1aeo.com", "172.64.0.1"),
    row("u4.bbbbbbbb.tor.exit.validator.1aeo.com", "198.51.100.1"),  # ASN lookup fails
    row("u5.dddddddd.tor.exit.validator.1aeo.com", "192.0.2.10", sample=1),
    row("chk-x.tor.exit.validator.1aeo.com", "1.1.1.1"),              # not an exit
    row("www.1aeo.com", "8.8.8.8"),                                   # not the validator zone
]
WEIGHTS = {FP_A: 0.3, FP_B: 0.1, FP_D: 0.6}


def run(report, rows=ROWS, previous=None, weights=WEIGHTS):
    return add_resolver_stats(report, rows, previous, lookup=lambda ip: PROVIDERS.get(ip, "unknown"),
                              weights=weights)


class TestResolverStats(unittest.TestCase):

    def test_attribution_sampling_and_labels(self):
        report = make_report()
        s = run(report)
        a, b, c, d = report["results"]
        self.assertEqual(a["resolver"], {"primary": "google", "public": True,
                                         "queries": {"google": 30, "other": 10}})
        # 10 known queries: seen (>=5) but below the label threshold (25)
        self.assertEqual(b["resolver"], {"primary": None, "public": None,
                                         "queries": {"cloudflare": 10, "unknown": 10}})
        self.assertNotIn("resolver", c)
        self.assertEqual(d["resolver"]["queries"], {"other": 1})
        self.assertEqual((s["rows"], s["est_queries"]), (8, 71))  # www.1aeo.com excluded, chk- counted

    def test_weighted_summary(self):
        s = run(make_report())
        # A: 0.3 * 30/40 google; B: 0.1 * 10/10 cloudflare ("unknown" excluded); D below "seen"
        self.assertEqual(s["public_share_pct"],
                         {"google": 56.25, "cloudflare": 25.0, "quad9": 0.0, "opendns": 0.0, "all": 81.25})
        self.assertEqual((s["exits_total"], s["exits_covered"], s["exits_labelled"], s["exits_using_public"]),
                         (3, 2, 1, 1))
        self.assertTrue(s["weighted"])
        self.assertEqual(s["window"], {"start": "2026-10-11T19:00:19Z", "end": "2026-10-11T19:27:04Z"})

    def test_unweighted_fallback(self):
        s = run(make_report(), weights={})
        self.assertFalse(s["weighted"])
        self.assertEqual(s["public_share_pct"]["google"], 37.5)
        self.assertEqual(s["public_share_pct"]["cloudflare"], 50.0)

    def test_carry_forward_decay(self):
        previous = make_report(timestamp="2026-10-08T07:26:08.878754Z")  # 84 h earlier: one half-life
        previous["metadata"]["resolvers"] = {"version": 1}
        prev_q = {FP_A: {"quad9": 20}, FP_C: {"google": 8}, FP_D: {"other": 50}}
        for r in previous["results"]:
            if r["exit_fingerprint"] in prev_q:
                r["resolver"] = {"queries": prev_q[r["exit_fingerprint"]]}
        report = make_report()
        s = run(report, previous=previous)
        a, b, c, d = report["results"]
        self.assertEqual(a["resolver"]["queries"], {"google": 30, "other": 10, "quad9": 10.0})
        self.assertEqual(c["resolver"]["queries"], {"google": 4.0})  # carried without new rows
        self.assertEqual(d["resolver"], {"primary": "other", "public": False, "queries": {"other": 26.0}})
        self.assertEqual((s["exits_covered"], s["exits_labelled"], s["exits_using_public"]), (3, 2, 1))

    def test_no_rows_raises_and_leaves_report(self):
        report = make_report()
        with self.assertRaises(RuntimeError):
            run(report, rows=[row("www.1aeo.com", "8.8.8.8")])
        self.assertEqual(report, make_report())

    def test_load_previous_skips_current_and_reports_without_data(self):
        with tempfile.TemporaryDirectory() as d:
            def write(name, with_data):
                rep = make_report()
                if with_data:
                    rep["metadata"]["resolvers"] = {"version": 1, "name": name}
                with open(os.path.join(d, name), "w") as f:
                    json.dump(rep, f)
                return os.path.join(d, name)
            write("dns_health_2026-10-10_12-05-01.json", True)
            write("dns_health_2026-10-11_00-05-01.json", True)
            write("dns_health_2026-10-11_12-05-01.json", False)  # stats failed that run
            latest = write("latest.json", False)
            current = write("dns_health_2026-10-12_00-05-01.json", True)
            prev = load_previous(latest, current)
            self.assertEqual(prev["metadata"]["resolvers"]["name"], "dns_health_2026-10-11_00-05-01.json")
            self.assertIsNone(load_previous(None, current))


class TestGraphqlPaging(unittest.TestCase):

    def test_pages_without_dropping_or_repeating_boundary_rows(self):
        data = [{"datetime": f"2026-10-11T19:10:0{s}Z", "queryName": f"q{i}.x", "sourceIP": "8.8.8.8",
                 "sampleInterval": 10} for i, s in enumerate([0, 1, 1, 1, 2, 2, 3, 4, 4, 5])]
        calls = []

        def fake_urlopen(req, timeout=None):
            body = json.loads(req.data)
            calls.append(body["variables"]["f"])
            self.assertEqual(req.get_header("Authorization"), "Bearer tok")
            self.assertEqual(body["variables"]["z"], "zone")
            f = body["variables"]["f"]
            hit = [r for r in data if r["datetime"] <= f["datetime_leq"]
                   and r["datetime"] >= f.get("datetime_geq", "") and r["datetime"] > f.get("datetime_gt", "")]
            out = {"data": {"viewer": {"zones": [{"dnsAnalyticsAdaptive": hit[:resolver_stats.PAGE_SIZE]}]}}}
            return io.BytesIO(json.dumps(out).encode())

        with mock.patch.object(resolver_stats, "PAGE_SIZE", 3), \
             mock.patch.object(resolver_stats.urllib.request, "urlopen", fake_urlopen), \
             mock.patch.dict(os.environ, {"CF_ZONE_ID": "zone", "CF_ANALYTICS_TOKEN": "tok"}):
            rows = graphql_rows("2026-10-11T19:10:00Z", "2026-10-11T19:10:09Z", "x")
        self.assertEqual([r["queryName"] for r in rows], [r["queryName"] for r in data])
        self.assertTrue(all(c["queryName_like"] == "%.x" for c in calls))

    def test_graphql_errors_raise(self):
        err = io.BytesIO(json.dumps({"data": None, "errors": [{"message": "bad"}]}).encode())
        with mock.patch.object(resolver_stats.urllib.request, "urlopen", return_value=err), \
             mock.patch.dict(os.environ, {"CF_ZONE_ID": "zone", "CF_ANALYTICS_TOKEN": "tok"}):
            with self.assertRaises(RuntimeError):
                graphql_rows("2026-10-11T19:10:00Z", "2026-10-11T19:10:09Z", "x")


class TestAsnProvider(unittest.TestCase):

    def lookup(self, ip, answer):
        queried = []

        def resolve(name, rdtype, lifetime=None):
            queried.append(name)
            if answer is None:
                raise OSError("timeout")
            return [types.SimpleNamespace(to_text=lambda: '"%s | 1.2.3.0/24 | US | arin |"' % answer)]
        fake = types.ModuleType("dns")
        fake.resolver = types.SimpleNamespace(resolve=resolve)
        with mock.patch.dict(sys.modules, {"dns": fake, "dns.resolver": fake.resolver}):
            return asn_provider(ip), queried

    def test_ipv4_google(self):
        self.assertEqual(self.lookup("8.8.4.4", "15169"), ("google", ["4.4.8.8.origin.asn.cymru.com"]))

    def test_ipv6_cloudflare_shortened_address(self):
        provider, (name,) = self.lookup("2a06:98c1:53::", "13335")
        self.assertEqual(provider, "cloudflare")
        self.assertTrue(name.endswith(".1.c.8.9.6.0.a.2.origin6.asn.cymru.com"))
        self.assertEqual(len(name.split(".")), 32 + 4)

    def test_other_multi_origin_and_failure(self):
        self.assertEqual(self.lookup("192.0.2.1", "64500")[0], "other")
        self.assertEqual(self.lookup("192.0.2.1", "64500 19281")[0], "quad9")
        self.assertEqual(self.lookup("192.0.2.1", None)[0], "unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
