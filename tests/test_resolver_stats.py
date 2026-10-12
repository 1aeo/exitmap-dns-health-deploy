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

import ipaddress
import resolver_stats
from resolver_stats import add_resolver_stats, graphql_rows, load_previous, origin_asns, published_ranges

FP_A, FP_B, FP_C, FP_D = ("AAAAAAAA" + "1" * 32, "BBBBBBBB" + "2" * 32,
                          "CCCCCCCC" + "3" * 32, "DDDDDDDD" + "4" * 32)
RANGES = {"google": [ipaddress.ip_network("8.8.8.0/24"), ipaddress.ip_network("2001:4860::/32")],
          "cloudflare": [ipaddress.ip_network("172.64.0.0/13"), ipaddress.ip_network("203.0.113.0/24")],
          "ffmuc": [ipaddress.ip_network("5.1.66.0/24")]}
ORIGINS = {"192.0.2.10": {64500}, "192.0.2.99": {64500}, "203.0.113.5": {64501},
           "74.63.16.1": {42}, "35.192.0.1": {396982}}  # anything else: lookup failed


def row(name, ip, sample=10):
    return {"datetime": "2026-10-11T19:10:00Z", "queryName": name, "sourceIP": ip, "sampleInterval": sample}


def make_report(timestamp="2026-10-11T19:26:08.878754Z"):
    return {"metadata": {"timestamp": timestamp}, "results": [
        {"exit_fingerprint": FP_A, "status": "success", "timestamp": 1791745519.8, "exit_address": "203.0.113.5"},
        {"exit_fingerprint": FP_B, "status": "success", "timestamp": 1791746524.9, "exit_address": "203.0.113.6"},
        {"exit_fingerprint": FP_C, "status": "timeout", "timestamp": 1791746000.0, "exit_address": "203.0.113.7"},
        {"exit_fingerprint": FP_D, "status": "success", "timestamp": 1791746100.0, "exit_address": "192.0.2.99"},
    ]}


ROWS = [
    row("u1.aaaaaaaa.tor.exit.validator.1aeo.com", "8.8.8.8"),
    row("u1.aaaaaaaa.tor.exit.validator.1aeo.com", "8.8.8.8"),
    row("aaaaaaaa.tor.exit.validator.1aeo.com", "2001:4860::1"),    # qname-minimised
    row("U2.AAAAAAAA.Tor.Exit.Validator.1aeo.com.", "192.0.2.10"),  # mixed case, trailing dot
    row("u3.bbbbbbbb.tor.exit.validator.1aeo.com", "172.64.0.1"),
    row("u4.bbbbbbbb.tor.exit.validator.1aeo.com", "198.51.100.1"),  # AS lookup fails
    row("u5.dddddddd.tor.exit.validator.1aeo.com", "192.0.2.10", sample=1),  # D's own network
    row("chk-x.tor.exit.validator.1aeo.com", "1.1.1.1"),              # not an exit
    row("www.1aeo.com", "8.8.8.8"),                                   # not the validator zone
]
WEIGHTS = {FP_A: 0.3, FP_B: 0.1, FP_D: 0.6}


def run(report, rows=ROWS, previous=None, weights=WEIGHTS, origins=ORIGINS):
    return add_resolver_stats(report, rows, previous, ranges=RANGES, origin=origins.get, weights=weights)


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
        self.assertEqual(d["resolver"]["queries"], {"local": 1})
        self.assertEqual((s["rows"], s["est_queries"]), (8, 71))  # www.1aeo.com excluded, chk- counted

    def test_weighted_summary(self):
        s = run(make_report())
        # A: 0.3 * 30/40 google; B: 0.1 * 10/10 cloudflare ("unknown" excluded); D below "seen"
        self.assertEqual(s["public_share_pct"],
                         {"google": 56.25, "cloudflare": 25.0, "quad9": 0.0, "opendns": 0.0, "ffmuc": 0.0,
                          "all": 81.25})
        self.assertEqual((s["exits_total"], s["exits_covered"], s["exits_labelled"], s["exits_using_public"]),
                         (3, 2, 1, 1))
        self.assertTrue(s["weighted"])
        self.assertEqual(s["share_pct"], {"google": 56.25, "cloudflare": 25.0, "quad9": 0.0, "opendns": 0.0,
                                          "ffmuc": 0.0, "local": 0.0, "other": 18.75})
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
        self.assertEqual(d["resolver"], {"primary": "other", "public": False, "queries": {"local": 1, "other": 25.0}})
        self.assertEqual((s["exits_covered"], s["exits_labelled"], s["exits_using_public"]), (3, 2, 1))

    def test_no_rows_raises_and_leaves_report(self):
        report = make_report()
        with self.assertRaises(RuntimeError):
            run(report, rows=[row("www.1aeo.com", "8.8.8.8")])
        self.assertEqual(report, make_report())

    def test_load_previous_only_strictly_older_reports(self):
        with tempfile.TemporaryDirectory() as d:
            def write(name, ts, with_data):
                rep = make_report(timestamp=ts)
                if with_data:
                    rep["metadata"]["resolvers"] = {"version": 1, "name": name}
                with open(os.path.join(d, name), "w") as f:
                    json.dump(rep, f)
                return os.path.join(d, name)
            write("dns_health_2026-10-10_12-05-01.json", "2026-10-10T19:26:00Z", True)
            write("dns_health_2026-10-11_00-05-01.json", "2026-10-11T07:26:00Z", True)
            write("dns_health_2026-10-11_12-05-01.json", "2026-10-11T19:26:00Z", False)  # stats failed
            current = write("dns_health_2026-10-12_00-05-01.json", "2026-10-12T07:26:00Z", True)
            write("dns_health_2026-10-12_12-05-01.json", "2026-10-12T19:26:00Z", True)  # newer: ignored
            # re-run case: latest.json is a copy of the current report -> not "previous"
            latest = write("latest.json", "2026-10-12T07:26:00Z", True)
            prev = load_previous(latest, current, resolver_stats.epoch("2026-10-12T07:26:00Z"))
            self.assertEqual([p["metadata"]["resolvers"]["name"] for p in prev],
                             ["dns_health_2026-10-11_00-05-01.json", "dns_health_2026-10-10_12-05-01.json"])
            self.assertEqual(load_previous(None, current, 0), [])

    def test_exit_missing_from_newest_previous_is_carried_from_older(self):
        older = make_report(timestamp="2026-10-04T19:26:08Z")       # 7 days = 2 half-lives
        older["metadata"]["resolvers"] = {"version": 1}
        older["results"][2]["resolver"] = {"queries": {"google": 400}}
        newer = make_report(timestamp="2026-10-11T07:26:08Z")
        newer["metadata"]["resolvers"] = {"version": 1}
        del newer["results"][2]                                       # exit C missing from that scan
        report = make_report()
        run(report, previous=[newer, older])
        self.assertEqual(report["results"][2]["resolver"]["queries"], {"google": 100.0})

    def test_previous_not_older_raises(self):
        same = make_report()
        same["metadata"]["resolvers"] = {"version": 1}
        report = make_report()
        with self.assertRaises(RuntimeError):
            run(report, previous=same)
        self.assertEqual(report, make_report())

    def test_stale_providers_expire_and_public_follows_primary(self):
        # one stray google row plus the exit's own resolver; afterwards only its own resolver
        rows0 = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "8.8.8.8")] + \
                [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "192.0.2.10")] * 5
        rows_n = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "192.0.2.10")] * 2
        prev = None
        for i in range(60):                                           # 30 days of 12-hourly scans
            report = make_report(timestamp=resolver_stats.iso(1791745568 + i * 43200))
            run(report, rows=rows0 if i == 0 else rows_n, previous=prev)
            a = report["results"][0]["resolver"]
            if i == 0:
                self.assertEqual(a, {"primary": "other", "public": False, "queries": {"google": 10, "other": 50}})
            prev = report
        self.assertNotIn("google", a["queries"])                     # decayed below one query and purged
        self.assertEqual((a["primary"], a["public"]), ("other", False))
        self.assertEqual(report["metadata"]["resolvers"]["exits_using_public"], 0)

    def test_lookup_outage_aborts_without_touching_report(self):
        report = make_report()
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "192.0.2.10")] * 3 + \
               [row("u.bbbbbbbb.tor.exit.validator.1aeo.com", "8.8.8.8")]  # list-matched: needs no AS lookup
        with self.assertRaises(RuntimeError):
            run(report, rows=rows, origins={})                  # 30 of 40 estimated queries unknown
        self.assertEqual(report, make_report())
        run(report, rows=rows[2:], origins={})                  # 10 of 20 unknown: at the limit, still published
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"unknown": 10})

    def test_classification_rules(self):
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", ip) for ip in
                ("2001:4860:1::5", "172.70.1.1", "74.63.16.1", "35.192.0.1")] + \
               [row("u.dddddddd.tor.exit.validator.1aeo.com", ip) for ip in ("192.0.2.10", "35.192.0.1")] + \
               [row("u.bbbbbbbb.tor.exit.validator.1aeo.com", ip) for ip in ("5.1.66.3", "203.0.113.6")]
        report = make_report()
        run(report, rows=rows)
        a, d = report["results"][0], report["results"][3]
        # published Google/Cloudflare ranges; Quad9 by PCH/WoodyNet origin AS; a Google Cloud
        # (AS396982) address outside Google's egress list is NOT google
        self.assertEqual(a["resolver"]["queries"], {"cloudflare": 10, "google": 10, "other": 10, "quad9": 10})
        self.assertEqual(d["resolver"]["queries"], {"local": 10, "other": 10})
        # Freifunk Muenchen's published range; the exit's own address is local even if inside a range
        self.assertEqual(report["results"][1]["resolver"]["queries"], {"ffmuc": 10, "local": 10})


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

    def test_bad_token_rejected_without_echo(self):
        with mock.patch.dict(os.environ, {"CF_ZONE_ID": "zone", "CF_ANALYTICS_TOKEN": "\u201csecret-value\u201d"}):
            with self.assertRaises(RuntimeError) as ctx:
                graphql_rows("2026-10-11T19:10:00Z", "2026-10-11T19:10:09Z", "x")
        self.assertNotIn("secret-value", str(ctx.exception))

    def test_graphql_errors_raise(self):
        err = io.BytesIO(json.dumps({"data": None, "errors": [{"message": "bad"}]}).encode())
        with mock.patch.object(resolver_stats.urllib.request, "urlopen", return_value=err), \
             mock.patch.dict(os.environ, {"CF_ZONE_ID": "zone", "CF_ANALYTICS_TOKEN": "tok"}):
            with self.assertRaises(RuntimeError):
                graphql_rows("2026-10-11T19:10:00Z", "2026-10-11T19:10:09Z", "x")


class TestLookups(unittest.TestCase):

    def origin(self, ip, *answers):
        queried = []

        def resolve(name, rdtype, lifetime=None):
            queried.append(name)
            if not answers:
                raise OSError("timeout")
            return [types.SimpleNamespace(to_text=lambda a=a: '"%s | US | arin |"' % a) for a in answers]
        fake = types.ModuleType("dns")
        fake.resolver = types.SimpleNamespace(resolve=resolve)
        with mock.patch.dict(sys.modules, {"dns": fake, "dns.resolver": fake.resolver}):
            return origin_asns(ip), queried

    def test_ipv4_query_name(self):
        self.assertEqual(self.origin("8.8.4.4", "15169 | 8.8.4.0/24"), ({15169}, ["4.4.8.8.origin.asn.cymru.com"]))

    def test_ipv6_query_name_for_shortened_address(self):
        asns, (name,) = self.origin("2a06:98c1:53::", "13335 | 2a06:98c0::/29")
        self.assertEqual(asns, {13335})
        self.assertTrue(name.endswith(".1.c.8.9.6.0.a.2.origin6.asn.cymru.com"))
        self.assertEqual(len(name.split(".")), 32 + 4)

    def test_most_specific_prefix_wins_and_failure_is_none(self):
        self.assertEqual(self.origin("192.0.2.1", "64500 | 192.0.0.0/16", "42 715 | 192.0.2.0/24")[0], {42, 715})
        self.assertEqual(self.origin("192.0.2.1", "42 | 192.0.2.0/24", "64500 | 192.0.0.0/16")[0], {42})
        self.assertIsNone(self.origin("192.0.2.1")[0])

    def test_published_ranges_and_fallbacks(self):
        google = {"prefixes": [{"ipv4Prefix": f"34.64.{i}.0/24", "service": "Google Public DNS"} for i in range(150)]
                              + [{"ipv6Prefix": "2001:4860:4860::/48", "service": "Google Public DNS"}]}
        cloudflare = {"result": {"ipv4_cidrs": ["172.64.0.0/13"], "ipv6_cidrs": ["2400:cb00::/32"]}}

        def ok(url, timeout=None):
            return io.BytesIO(json.dumps(google if "gstatic" in url else cloudflare).encode())
        with mock.patch.object(resolver_stats.urllib.request, "urlopen", ok):
            r = published_ranges()
        self.assertEqual((len(r["google"]), [str(n) for n in r["cloudflare"]]), (151, ["172.64.0.0/13", "2400:cb00::/32"]))

        def down(url, timeout=None):
            raise OSError("unreachable")
        txt = [types.SimpleNamespace(strings=[f"34.64.{i}.0/24 icn ".encode() for i in range(120)])]
        fake = types.ModuleType("dns")
        fake.resolver = types.SimpleNamespace(resolve=lambda name, rdtype, lifetime=None: txt)
        with mock.patch.object(resolver_stats.urllib.request, "urlopen", down), \
             mock.patch.dict(sys.modules, {"dns": fake, "dns.resolver": fake.resolver}):
            r = published_ranges()                       # Google from the TXT record, Cloudflare snapshot
        self.assertEqual((len(r["google"]), len(r["cloudflare"])), (120, len(resolver_stats.CLOUDFLARE_SNAPSHOT)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
