#!/usr/bin/env python3
"""
Tests for scripts/resolver_stats.py (sampled DNS analytics -> per-exit resolver estimates)

Run: python -m pytest tests/test_resolver_stats.py -v
Or:  python tests/test_resolver_stats.py
"""

import gzip
import io
import json
import os
import sys
import tempfile
import types
import unittest
import urllib.error
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
# A slice of the Public Suffix List (https://publicsuffix.org/list/public_suffix_list.dat).
SUFFIXES = frozenset({"com", "net", "org", "de", "se", "uk", "co.uk", "jp", "tokyo.jp", "*.kawasaki.jp",
                      "!city.kawasaki.jp", "pl", "warszawa.pl", "eu", "ddnss.eu", "dyndns.org", "hopto.org",
                      "in-berlin.de", "test", "example", "cn", "xn--55qx5d.cn"})
ORIGINS = {"192.0.2.10": {64500}, "192.0.2.99": {64500}, "203.0.113.5": {64501},
           "74.63.16.1": {42}, "35.192.0.1": {396982}}  # anything else: lookup failed


def row(name, ip, sample=10):
    """One sampled dnsAnalyticsAdaptive row."""
    return {"datetime": "2026-10-11T19:10:00Z", "queryName": name, "sourceIP": ip, "sampleInterval": sample}


def make_report(timestamp="2026-10-11T19:26:08.878754Z"):
    """Minimal scan report: exits A, B, D succeeded, C timed out."""
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


def run(report, rows=ROWS, previous=None, weights=WEIGHTS, origins=ORIGINS, relays=(),
        aroi=(), fcrdns=None, suffixes=SUFFIXES):
    """add_resolver_stats with fixed ranges, AS data, exit weights and suffix rules (no network)."""
    return add_resolver_stats(report, rows, previous, ranges=RANGES, origin=origins.get, weights=weights,
                              relays=list(relays), aroi=list(aroi),
                              fcrdns=fcrdns or (lambda ip: set()), suffixes=suffixes)


class TestResolverStats(unittest.TestCase):

    def test_attribution_sampling_and_labels(self):
        """Rows map to exits by fp8 (any case, minimised names), weighted by sampleInterval."""
        report = make_report()
        s = run(report)
        a, b, c, d = report["results"]
        self.assertEqual(a["resolver"], {"primary": "google", "public": True,
                                         "queries": {"google": 30, "other": 10}})
        # 20 queries (unknown included): seen (>=5) but below the label threshold (25)
        self.assertEqual(b["resolver"], {"primary": None, "public": None,
                                         "queries": {"cloudflare": 10, "unknown": 10}})
        self.assertNotIn("resolver", c)
        self.assertEqual(d["resolver"]["queries"], {"local_24": 1})
        self.assertEqual((s["rows"], s["est_queries"]), (8, 71))  # www.1aeo.com excluded, chk- counted

    def test_weighted_summary(self):
        """Shares are exit-probability-weighted means of per-exit fractions over seen exits."""
        s = run(make_report())
        # A: 0.3 * 30/40 google; B: 0.1 * 10/20 cloudflare (its "unknown" half counts too); D below "seen"
        self.assertEqual(s["public_share_pct"],
                         {"google": 56.25, "cloudflare": 12.5, "quad9": 0.0, "opendns": 0.0, "ffmuc": 0.0,
                          "all": 68.75})
        self.assertEqual((s["exits_total"], s["exits_covered"], s["exits_labelled"], s["exits_using_public"]),
                         (3, 2, 1, 1))
        self.assertTrue(s["weighted"])
        self.assertEqual(s["version"], 2)
        self.assertEqual(s["share_pct"], {"google": 56.25, "cloudflare": 12.5, "quad9": 0.0, "opendns": 0.0,
                                          "ffmuc": 0.0, "local_24": 0.0, "local_22": 0.0, "local_as": 0.0,
                                          "local_operator": 0.0, "other": 18.75, "unknown": 12.5})
        self.assertNotIn("local", s["share_pct"])
        self.assertEqual(s["operator_sources"], {"onionoo": True, "aroi": True, "public_suffix_list": True})
        self.assertEqual(s["window"], {"start": "2026-10-11T19:00:19Z", "end": "2026-10-11T19:27:04Z"})

    def test_unweighted_fallback(self):
        """Without Onionoo weights every seen exit counts equally."""
        s = run(make_report(), weights={})
        self.assertFalse(s["weighted"])
        self.assertEqual(s["public_share_pct"]["google"], 37.5)
        self.assertEqual(s["public_share_pct"]["cloudflare"], 25.0)

    def test_carry_forward_decay(self):
        """Earlier counts decay with the 84 h half-life before new rows are added."""
        previous = make_report(timestamp="2026-10-08T07:26:08.878754Z")  # 84 h earlier: one half-life
        previous["metadata"]["resolvers"] = {"version": 2}
        prev_q = {FP_A: {"quad9": 20}, FP_C: {"google": 8}, FP_D: {"other": 50}}
        for r in previous["results"]:
            if r["exit_fingerprint"] in prev_q:
                r["resolver"] = {"queries": prev_q[r["exit_fingerprint"]]}
        report = make_report()
        s = run(report, previous=previous)
        a, b, c, d = report["results"]
        self.assertEqual(a["resolver"]["queries"], {"google": 30, "other": 10, "quad9": 10.0})
        self.assertEqual(c["resolver"]["queries"], {"google": 4.0})  # carried without new rows
        self.assertEqual(d["resolver"], {"primary": "other", "public": False,
                                         "queries": {"local_24": 1, "other": 25.0}})
        self.assertEqual((s["exits_covered"], s["exits_labelled"], s["exits_using_public"]), (3, 2, 1))

    def test_no_rows_raises_and_leaves_report(self):
        """No validator rows in the window: raise, report untouched."""
        report = make_report()
        with self.assertRaises(RuntimeError):
            run(report, rows=[row("www.1aeo.com", "8.8.8.8")])
        self.assertEqual(report, make_report())

    def test_load_previous_only_strictly_older_reports(self):
        """Only strictly older version-2 reports, newest first."""
        with tempfile.TemporaryDirectory() as d:
            def write(name, ts, with_data, version=2):
                """Write a report into the temp dir and return its path."""
                rep = make_report(timestamp=ts)
                if with_data:
                    rep["metadata"]["resolvers"] = {"version": version, "name": name}
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

    def test_load_previous_skips_version1_and_prefers_dns_health_over_latest(self):
        """A stale v1 latest.json cannot hide the rewritten v2 report of the same scan."""
        with tempfile.TemporaryDirectory() as d:
            def write(name, ts, version):
                """Write a report with resolver data of the given version."""
                rep = make_report(timestamp=ts)
                rep["metadata"]["resolvers"] = {"version": version, "name": name}
                with open(os.path.join(d, name), "w") as f:
                    json.dump(rep, f)
                return os.path.join(d, name)
            write("dns_health_2026-10-10_12-05-01.json", "2026-10-10T19:26:00Z", 1)   # not rewritten
            write("dns_health_2026-10-11_00-05-01.json", "2026-10-11T07:26:00Z", 2)   # rewritten twin
            latest = write("latest.json", "2026-10-11T07:26:00Z", 1)                  # stale v1 copy
            current = os.path.join(d, "dns_health_2026-10-11_12-05-01.json")
            with open(current, "w") as f:
                json.dump(make_report(timestamp="2026-10-11T19:26:00Z"), f)
            prev = load_previous(latest, current, resolver_stats.epoch("2026-10-11T19:26:00Z"))
            self.assertEqual([p["metadata"]["resolvers"]["name"] for p in prev],
                             ["dns_health_2026-10-11_00-05-01.json"])

    def test_exit_missing_from_newest_previous_is_carried_from_older(self):
        """An exit absent from the newest report keeps its older counts."""
        older = make_report(timestamp="2026-10-04T19:26:08Z")       # 7 days = 2 half-lives
        older["metadata"]["resolvers"] = {"version": 2}
        older["results"][2]["resolver"] = {"queries": {"google": 400}}
        newer = make_report(timestamp="2026-10-11T07:26:08Z")
        newer["metadata"]["resolvers"] = {"version": 2}
        del newer["results"][2]                                       # exit C missing from that scan
        report = make_report()
        run(report, previous=[newer, older])
        self.assertEqual(report["results"][2]["resolver"]["queries"], {"google": 100.0})

    def test_previous_not_older_raises(self):
        """A previous report that is not older (e.g. a re-run) is refused."""
        same = make_report()
        same["metadata"]["resolvers"] = {"version": 2}
        report = make_report()
        with self.assertRaises(RuntimeError):
            run(report, previous=same)
        self.assertEqual(report, make_report())

    def test_stale_providers_expire_and_public_follows_primary(self):
        """Stray rows decay out below one query; public follows primary."""
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
        """An origin-AS outage aborts even when prefix tiers keep 'unknown' small."""
        report = make_report()
        # D's resolver shares its /24, so it would be local_24 without any AS data: under the old
        # unknown-share guard only A's 10 queries (of 50) would be unknown and the run would publish.
        rows = [row("u.dddddddd.tor.exit.validator.1aeo.com", "192.0.2.10")] * 4 + \
               [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "198.51.100.1")]
        with self.assertRaises(RuntimeError):
            run(report, rows=rows, origins={})                  # every lookup failed
        self.assertEqual(report, make_report())
        partial = dict(ORIGINS, **{"203.0.113.6": {64502}})      # only 198.51.100.1 fails
        run(report, rows=rows, origins=partial)
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"unknown": 10})
        self.assertEqual(report["results"][3]["resolver"]["queries"], {"local_24": 40})

    def test_unknown_counts_and_can_be_primary(self):
        """Queries without AS data still count toward shares; an 'unknown' primary has public=None."""
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "198.51.100.1")] * 3 + \
               [row("u.bbbbbbbb.tor.exit.validator.1aeo.com", "8.8.8.8")] * 4 + \
               [row("u.dddddddd.tor.exit.validator.1aeo.com", "192.0.2.10")] * 4
        report = make_report()
        s = run(report, rows=rows, weights={})                    # 30 of 70 looked-up queries failed
        self.assertEqual(report["results"][0]["resolver"], {"primary": "unknown", "public": None,
                                                           "queries": {"unknown": 30}})
        self.assertEqual((s["share_pct"]["unknown"], s["share_pct"]["google"], s["share_pct"]["local_24"]),
                         (33.33, 33.33, 33.33))
        self.assertEqual(s["exits_using_public"], 1)

    def test_classification_rules(self):
        """Published ranges, Quad9/OpenDNS ASNs, local vs other, and the exit's own address."""
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
        self.assertEqual(d["resolver"]["queries"], {"local_24": 10, "other": 10})
        # Freifunk Muenchen's published range; the exit's own address is local_24 even inside a range
        self.assertEqual(report["results"][1]["resolver"]["queries"], {"ffmuc": 10, "local_24": 10})


def _relay(fp, or_addresses, exit_addresses=(), family=(), contact="", probability=0.0):
    """One Onionoo relay record for an injected directory."""
    return {"fingerprint": fp, "or_addresses": list(or_addresses), "exit_addresses": list(exit_addresses),
            "effective_family": list(family) or [fp], "contact": contact, "exit_probability": probability}


def _exit_report(fp, exit_address, *extra):
    """A report whose first result is fp; extra is more result dicts."""
    results = [{"exit_fingerprint": fp, "status": "success", "timestamp": 1791745519.8,
                "exit_address": exit_address}]
    results.extend(extra)
    return {"metadata": {"timestamp": "2026-10-11T19:26:08.878754Z"}, "results": results}


class TestLocalTiers(unittest.TestCase):

    def test_prefix_tiers_ordering_and_public_rules(self):
        """Own address beats a public range; /24 beats /22 beats AS; public beats a prefix."""
        origins = {"192.0.2.10": {64500}, "192.0.2.20": {64500}, "192.0.1.20": {64500},
                   "192.0.4.20": {64500}, "8.8.8.8": {15169}, "8.8.8.9": {15169},
                   "208.67.222.222": {36692}}
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", ip) for ip in
                ("192.0.2.20", "192.0.1.20", "192.0.4.20", "203.0.113.9", "208.67.222.222")] + [
            row("u.bbbbbbbb.tor.exit.validator.1aeo.com", "8.8.8.8"),
            row("u.bbbbbbbb.tor.exit.validator.1aeo.com", "8.8.8.9")]
        report = _exit_report(FP_A, "192.0.2.10",
                              {"exit_fingerprint": FP_B, "status": "success", "timestamp": 1791745520.0,
                               "exit_address": "8.8.8.8"})
        run(report, rows=rows, origins=origins, weights={})
        # 203.0.113.9 is inside the fixture's Cloudflare range, so it is cloudflare and not local_24.
        # 208.67.222.222 is OpenDNS by AS36692. 8.8.8.8 is B's own address inside Google's range.
        self.assertEqual(report["results"][0]["resolver"]["queries"],
                         {"cloudflare": 10, "local_22": 10, "local_24": 10, "local_as": 10, "opendns": 10})
        self.assertEqual(report["results"][1]["resolver"]["queries"], {"google": 10, "local_24": 10})

    def test_ipv6_prefixes_do_not_match_ipv4(self):
        """IPv6 /64 is local_24 and IPv6 /48 is local_22; an IPv4 resolver does not match them."""
        v6 = "[2001:db8:1:2::10]:9001"
        origins = {"203.0.113.5": {9}, "2001:db8:1:2::10": {9}, "2001:db8:1:2::99": {9},
                   "2001:db8:1:3::10": {9}, "2001:db8:2::10": {8}, "192.0.2.10": {1}}
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", ip) for ip in
                ("2001:db8:1:2::10", "2001:db8:1:2::99", "2001:db8:1:3::10", "2001:db8:2::10", "192.0.2.10")]
        report = _exit_report(FP_A, "203.0.113.5")
        run(report, rows=rows, origins=origins, weights={},
            relays=[_relay(FP_A, ["203.0.113.5:9001", v6], ["203.0.113.5"])])
        self.assertEqual(report["results"][0]["resolver"]["queries"],
                         {"local_24": 20, "local_22": 10, "other": 20})

    def test_same_prefix_is_local_even_when_as_lookup_fails(self):
        """A /24 match does not become unknown, and does not trip the unknown-share abort."""
        report = _exit_report(FP_A, "192.0.2.10")
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "192.0.2.20")] * 3 + \
               [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "192.0.2.10")] * 4   # own address, AS known
        run(report, rows=rows, origins={"192.0.2.10": {64500}})                  # 192.0.2.20 lookup fails
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"local_24": 70})

    def test_operator_by_address_prefix_and_confirmed_name(self):
        """Group relay address, footprint /24 and /48, and FCrDNS match; a same-AS hit stays local_as."""
        contact = "email:ops[]example.net url:https://www.example.net/exit"
        family = ["$" + FP_A, FP_B, FP_C, FP_D]
        relays = [
            _relay(FP_A, ["198.51.100.10:9001"], ["198.51.100.10"], family, contact),
            _relay(FP_B, ["10.8.8.8:9001"], family=family),
            _relay(FP_C, ["10.7.7.8:9001", "[2001:db8:abcd::1]:9001"], family=family),
        ]
        aroi = [{"fingerprint": fp, "valid": True, "domain": "Example.NET"} for fp in (FP_A, FP_B, FP_C, FP_D)]
        origins = {"198.51.100.10": {50}, "10.8.8.8": {77}, "10.7.7.9": {77}, "10.1.2.3": {50},
                   "192.0.2.50": {77}, "192.0.2.51": {77}, "2001:db8:abcd:99::5": {77}}
        confirmed = {"192.0.2.50": {"dns.example.net"}, "192.0.2.51": set(),
                     "10.8.8.8": set(), "10.7.7.9": set(), "10.1.2.3": set(), "2001:db8:abcd:99::5": set()}
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", ip) for ip in
                ("10.8.8.8", "10.7.7.9", "2001:db8:abcd:99::5", "192.0.2.50", "192.0.2.51", "10.1.2.3")]
        # 10.1.2.3 shares the exit's AS, so it is local_as even though a group relay sits there.
        relays.append(_relay(FP_D, ["10.1.2.3:9001"], family=family))
        report = _exit_report(FP_A, "198.51.100.10")
        summary = run(report, rows=rows, origins=origins, weights={}, relays=relays, aroi=aroi,
                      fcrdns=confirmed.get)
        queries = report["results"][0]["resolver"]["queries"]
        self.assertEqual(queries, {"local_as": 10, "local_operator": 40, "other": 10})
        self.assertEqual(summary["operator_signals"], {"address": 10, "prefix": 20, "fcrdns": 10, "name": 0})
        self.assertEqual((report["results"][0]["resolver"]["primary"],
                          report["results"][0]["resolver"]["public"]), ("local_operator", False))

    def test_aroi_domain_alone_defines_the_operator_group(self):
        """Relays validated for the exit's domain form the group; shared ContactInfo does not."""
        contact = "email:ops[]example.net"
        relays = [
            _relay(FP_A, ["198.51.100.10:9001"], contact=contact),
            _relay(FP_B, ["10.4.4.4:9001"], contact="email:someone-else[]example.org"),
            _relay(FP_C, ["10.6.6.6:9001"], contact=contact),
        ]
        aroi = [{"fingerprint": FP_A, "valid": True, "domain": "example.net"},
                {"fingerprint": FP_B, "valid": True, "domain": "example.net"},
                {"fingerprint": FP_C, "valid": True, "domain": "other.example"}]
        origins = {"198.51.100.10": {50}, "10.4.4.4": {77}, "10.6.6.6": {77}}
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", ip) for ip in ("10.4.4.4", "10.6.6.6")]
        report = _exit_report(FP_A, "198.51.100.10")
        run(report, rows=rows, origins=origins, weights={}, relays=relays, aroi=aroi)
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"local_operator": 10, "other": 10})

    def test_no_operator_group_without_a_validated_domain(self):
        """Without a validated AROI domain, Tor family and identical ContactInfo do not make an operator."""
        family = [FP_A, FP_B]
        relays = [
            _relay(FP_A, ["198.51.100.10:9001"], family=family, contact="email:ops[]example.net"),
            _relay(FP_B, ["10.5.5.5:9001"], family=family, contact="email:ops[]example.net"),
        ]
        origins = {"198.51.100.10": {50}, "10.5.5.5": {77}}
        for aroi in ([], [{"fingerprint": FP_A, "valid": False, "domain": "example.net"},
                          {"fingerprint": FP_B, "valid": True, "domain": "example.net"}]):
            report = _exit_report(FP_A, "198.51.100.10")
            run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "10.5.5.5")],
                origins=origins, weights={}, relays=relays, aroi=aroi)
            self.assertEqual(report["results"][0]["resolver"]["queries"], {"other": 10})

    def test_aroi_or_onionoo_outage_leaves_the_report(self):
        """Operator identity needs AROI and addresses need Onionoo: either failing raises, nothing is published."""
        for fetcher in ("fetch_aroi", "fetch_onionoo"):
            untouched = make_report()
            with mock.patch.object(resolver_stats, fetcher, side_effect=RuntimeError("down")):
                with self.assertRaises(RuntimeError):
                    add_resolver_stats(untouched, ROWS, ranges=RANGES, origin=ORIGINS.get, weights=WEIGHTS,
                                       relays=None if fetcher == "fetch_onionoo" else [],
                                       aroi=None if fetcher == "fetch_aroi" else [], fcrdns=lambda ip: set(),
                                       suffixes=SUFFIXES)
            self.assertEqual(untouched, make_report())

    def test_fetch_aroi_retries_then_raises(self):
        """A malformed or unreachable aroivalidator file is retried, then raises."""
        with mock.patch.object(resolver_stats, "fetch_json", return_value={"results": "nope"}), \
             mock.patch.object(resolver_stats.time, "sleep"):
            with self.assertRaises(RuntimeError):
                resolver_stats.fetch_aroi()
        with mock.patch.object(resolver_stats, "fetch_json", return_value={"results": []}):
            self.assertEqual(resolver_stats.fetch_aroi(), [])

    def test_operator_name_matches_a_resolver_registered_at_its_hoster(self):
        """artikel10.in-berlin.de is not under artikel10.org, but is registered in the operator's name."""
        self.assertTrue(resolver_stats.name_in_domain("dns.dotsrc.org", "dotsrc.org"))
        self.assertTrue(resolver_stats.name_in_domain("dotsrc.org", "dotsrc.org"))
        self.assertFalse(resolver_stats.name_in_domain("artikel10.in-berlin.de", "artikel10.org"))
        self.assertFalse(resolver_stats.name_in_domain("notexample.net", "example.net"))
        relays = [_relay(FP_A, ["198.51.100.10:9001"])]
        aroi = [{"fingerprint": FP_A, "valid": True, "domain": "artikel10.org"}]
        origins = {"198.51.100.10": {60729}, "217.197.91.153": {29670}}
        report = _exit_report(FP_A, "198.51.100.10")
        run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "217.197.91.153")],
            origins=origins, weights={}, relays=relays, aroi=aroi,
            fcrdns=lambda ip: {"artikel10.in-berlin.de"} if ip == "217.197.91.153" else set())
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"local_operator": 10})
        self.assertEqual(report["metadata"]["resolvers"]["operator_signals"]["name"], 10)
        self.assertTrue(report["metadata"]["resolvers"]["operator_sources"]["public_suffix_list"])

    def test_operator_name_rule_stays_narrow(self):
        """No match from unverified ContactInfo, partial labels, names in someone else's zone, generic
        or short names, unconfirmed PTRs, or without the suffix list."""
        origins = {"198.51.100.10": {60729}, "217.197.91.153": {29670}}

        def queries(aroi, contact="", ptr="artikel10.in-berlin.de", suffixes=SUFFIXES):
            """Classify one row from 217.197.91.153 whose confirmed name is ptr."""
            report = _exit_report(FP_A, "198.51.100.10")
            run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "217.197.91.153")],
                origins=origins, weights={}, relays=[_relay(FP_A, ["198.51.100.10:9001"], contact=contact)],
                aroi=aroi, fcrdns=lambda ip: {ptr} if ptr and ip == "217.197.91.153" else set(),
                suffixes=suffixes)
            return report["results"][0]["resolver"]["queries"]
        valid = [{"fingerprint": FP_A, "valid": True, "domain": "artikel10.org"}]
        self.assertEqual(queries(valid, ptr="dns.artikel10.net"), {"local_operator": 10})  # registered name
        self.assertEqual(queries([], contact="url:https://artikel10.org"), {"other": 10})   # unverified contact
        self.assertEqual(queries([dict(valid[0], valid=False)]), {"other": 10})            # invalid AROI row
        self.assertEqual(queries(valid, ptr="artikel10x.in-berlin.de"), {"other": 10})      # partial label
        self.assertEqual(queries(valid, ptr="artikel10.attacker.test"), {"other": 10})      # someone else's zone
        self.assertEqual(queries(valid, ptr="artikel10.org.attacker.test"), {"other": 10})
        self.assertEqual(queries(valid, ptr=""), {"other": 10})                            # not forward-confirmed
        self.assertEqual(queries(valid, suffixes=frozenset()), {"other": 10})              # no suffix list
        self.assertEqual(queries([{"fingerprint": FP_A, "valid": True, "domain": "relay.example"}],
                                 ptr="relay.in-berlin.de"), {"other": 10})                  # generic name
        self.assertEqual(queries([{"fingerprint": FP_A, "valid": True, "domain": "dfri.se"}],
                                 ptr="dfri.in-berlin.de"), {"other": 10})                   # shorter than NAME_MIN

    def test_operator_name_from_domain(self):
        """The registrable label; empty for short, numeric or generic names, or without suffix rules."""
        name = resolver_stats.operator_name
        self.assertEqual(name("artikel10.org", SUFFIXES), "artikel10")
        self.assertEqual(name("relays.Zwiebelnet.ORG.", SUFFIXES), "zwiebelnet")
        self.assertEqual(name("www.applied-privacy.net", SUFFIXES), "applied-privacy")
        self.assertEqual(name("torrelays.co.uk", SUFFIXES), "torrelays")
        self.assertEqual(name("relays.zwiebel.tokyo.jp", SUFFIXES), "zwiebel")
        self.assertEqual(name("someone.dyndns.org", SUFFIXES), "someone")  # the user's name, not the platform's
        self.assertEqual(name("bundesgebaermutter.ddnss.eu", SUFFIXES), "bundesgebaermutter")
        for domain in ("dfri.se", "12345.net", "relay.net", "privacy.org", "localhost", "", None,
                       "relays.example.tokyo.jp", "x.warszawa.pl", "dyndns.org", "in-berlin.de",
                       "host.amazonaws.com"):
            self.assertEqual(name(domain, SUFFIXES), "", domain)
        self.assertEqual(name("artikel10.org", frozenset()), "")

    def test_idn_domain_and_punycode_ptr_compare_equal(self):
        """A Unicode AROI domain and the punycode PTR of a resolver at its hoster give the same name."""
        self.assertEqual(resolver_stats.operator_name("bücher.org", SUFFIXES), "xn--bcher-kva")
        self.assertEqual(resolver_stats.registrable_label("xn--bcher-kva.in-berlin.de", SUFFIXES), "xn--bcher-kva")
        self.assertEqual(resolver_stats.operator_name("bü.org", SUFFIXES), "")  # NAME_MIN counts "bü", not "xn--b-eha"
        relays = [_relay(FP_A, ["198.51.100.10:9001"])]
        report = _exit_report(FP_A, "198.51.100.10")
        run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "217.197.91.153")],
            origins={"198.51.100.10": {60729}, "217.197.91.153": {29670}}, weights={}, relays=relays,
            aroi=[{"fingerprint": FP_A, "valid": True, "domain": "Bücher.org"}],
            fcrdns=lambda ip: {"xn--bcher-kva.in-berlin.de"})
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"local_operator": 10})

    def test_unicode_and_punycode_aroi_spellings_form_one_group(self):
        """Relays validated as bücher.org and xn--bcher-kva.org are one operator; PTRs match either spelling."""
        relays = [_relay(FP_A, ["198.51.100.10:9001"]), _relay(FP_B, ["10.5.5.5:9001"])]
        aroi = [{"fingerprint": FP_A, "valid": True, "domain": "bücher.org"},
                {"fingerprint": FP_B, "valid": True, "domain": "XN--BCHER-KVA.org"}]
        origins = {"198.51.100.10": {50}, "10.5.5.5": {77}, "10.9.9.9": {78}}
        report = _exit_report(FP_A, "198.51.100.10")
        run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "10.5.5.5"),
                          row("v.aaaaaaaa.tor.exit.validator.1aeo.com", "10.9.9.9")],
            origins=origins, weights={}, relays=relays, aroi=aroi,
            fcrdns=lambda ip: {"ns.xn--bcher-kva.org"} if ip == "10.9.9.9" else set())
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"local_operator": 20})
        self.assertEqual(report["metadata"]["resolvers"]["operator_signals"],
                         {"address": 10, "prefix": 0, "fcrdns": 10, "name": 0})

    def test_punycode_keeps_distinct_names_distinct(self):
        """straße.de and xn--strae-oqa.de are one name, strasse.de another; compatibility forms are rejected."""
        puny = resolver_stats._punycode
        self.assertEqual(puny("Straße.DE."), "xn--strae-oqa.de")
        self.assertEqual(puny("xn--strae-oqa.de"), "xn--strae-oqa.de")
        self.assertEqual(puny("strasse.de"), "strasse.de")
        self.assertEqual(puny("公司.cn"), "xn--55qx5d.cn")
        self.assertEqual(puny("ｅxample.org"), "")  # fullwidth: IDNA 2008 maps or rejects it
        domain_of, by_domain = resolver_stats._index_aroi([
            {"fingerprint": FP_A, "valid": True, "domain": "straße.de"},
            {"fingerprint": FP_B, "valid": True, "domain": "xn--strae-oqa.de"},
            {"fingerprint": FP_C, "valid": True, "domain": "strasse.de"},
            {"fingerprint": FP_D, "valid": True, "domain": "ｅxample.org"}])
        self.assertEqual(dict(by_domain), {"xn--strae-oqa.de": {FP_A, FP_B}, "strasse.de": {FP_C}})
        self.assertEqual(resolver_stats.operator_name("straße.de", SUFFIXES), "xn--strae-oqa")

    def test_local_operator_counts_carry_only_from_aroi_identity_reports(self):
        """Earlier v2 reports (operators also from family/ContactInfo) do not carry local_operator."""
        relays = [_relay(FP_A, ["198.51.100.10:9001"])]
        origins = {"198.51.100.10": {60729}, "10.5.5.5": {77}}

        def previous(identity):
            """A report one half-life older with 100 local_operator and 40 local_24 queries for A."""
            prev = _exit_report(FP_A, "198.51.100.10")
            prev["metadata"]["timestamp"] = "2026-10-08T07:26:08Z"
            prev["metadata"]["resolvers"] = {"version": 2}
            if identity:
                prev["metadata"]["resolvers"]["operator_identity"] = identity
            prev["results"][0]["resolver"] = {"queries": {"local_operator": 100, "local_24": 40}}
            return prev
        for identity, expected in ((None, {"local_24": 20.0, "other": 10}),
                                   ("aroi", {"local_24": 20.0, "local_operator": 50.0, "other": 10})):
            report = _exit_report(FP_A, "198.51.100.10")
            run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "10.5.5.5")], previous=previous(identity),
                origins=origins, weights={}, relays=relays)
            self.assertEqual(report["results"][0]["resolver"]["queries"], expected, identity)
            self.assertEqual(report["metadata"]["resolvers"]["operator_identity"], "aroi")

    def test_registrable_label_follows_the_public_suffix_algorithm(self):
        """Longest rule wins, wildcards and exceptions apply, unlisted TLDs use the default rule."""
        label = resolver_stats.registrable_label
        self.assertEqual(label("artikel10.in-berlin.de", SUFFIXES), "artikel10")
        self.assertEqual(label("a.b.artikel10.in-berlin.de.", SUFFIXES), "artikel10")
        self.assertEqual(label("www.foo.co.uk", SUFFIXES), "foo")
        self.assertEqual(label("www.foo.bar.kawasaki.jp", SUFFIXES), "foo")       # *.kawasaki.jp
        self.assertEqual(label("www.city.kawasaki.jp", SUFFIXES), "city")         # !city.kawasaki.jp
        self.assertEqual(label("host.foo.unlisted", SUFFIXES), "foo")             # default rule "*"
        self.assertEqual(label("xn--55qx5d.cn", SUFFIXES), "")                    # a suffix itself
        self.assertEqual(label("host.foo.xn--55qx5d.cn", SUFFIXES), "foo")
        for bad in ("co.uk", "in-berlin.de", "org", "", None, "a..org"):
            self.assertEqual(label(bad, SUFFIXES), "", bad)

    def test_parse_suffixes_reads_rules_and_skips_comments(self):
        """Rules end at whitespace, comments and blank lines are skipped, IDN rules become ASCII."""
        text = "// ===BEGIN ICANN DOMAINS===\n\nCO.uk extra\n*.kawasaki.jp\n!city.kawasaki.jp\n公司.cn\n// x\n"
        self.assertEqual(resolver_stats.parse_suffixes(text),
                         {"co.uk", "*.kawasaki.jp", "!city.kawasaki.jp", "xn--55qx5d.cn"})

    def test_public_suffixes_cache_once_a_day_with_stale_fallback(self):
        """Fetched at most once a day; a failed fetch uses a cached copy up to 30 days old, else no rules."""
        good = "// ===BEGIN ICANN DOMAINS===\norg\n// ===BEGIN PRIVATE DOMAINS===\nin-berlin.de\n"
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"DEPLOY_DIR": tmp}):
            path = os.path.join(tmp, "data", "public_suffix_list.dat")
            with mock.patch.object(resolver_stats, "fetch_text", side_effect=OSError("down")):
                self.assertEqual(resolver_stats.public_suffixes(), frozenset())        # nothing cached
            with mock.patch.object(resolver_stats, "fetch_text", return_value="<html>captive portal</html>"):
                self.assertEqual(resolver_stats.public_suffixes(), frozenset())        # not the list
            self.assertFalse(os.path.exists(path))
            with mock.patch.object(resolver_stats, "fetch_text", return_value=good) as fetch:
                self.assertEqual(resolver_stats.public_suffixes(), {"org", "in-berlin.de"})
                self.assertEqual(resolver_stats.public_suffixes(), {"org", "in-berlin.de"})
                self.assertEqual(fetch.call_count, 1)                                  # second call: cache
            two_days_ago = os.path.getmtime(path) - 2 * 86400
            os.utime(path, (two_days_ago, two_days_ago))
            with mock.patch.object(resolver_stats, "fetch_text", side_effect=OSError("down")) as fetch:
                self.assertEqual(resolver_stats.public_suffixes(), {"org", "in-berlin.de"})  # stale copy
                self.assertEqual(fetch.call_count, 1)
            old = os.path.getmtime(path) - 40 * 86400
            os.utime(path, (old, old))
            with mock.patch.object(resolver_stats, "fetch_text", side_effect=OSError("down")):
                self.assertEqual(resolver_stats.public_suffixes(), frozenset())        # too old

    def test_non_string_aroi_domain_is_ignored(self):
        """A non-string AROI domain is skipped and classification still finishes."""
        relays = [_relay(FP_A, ["198.51.100.10:9001"]), _relay(FP_B, ["10.5.5.5:9001"])]
        aroi = [{"fingerprint": FP_A, "valid": True, "domain": {"name": "example.net"}},
                {"fingerprint": FP_B, "valid": True, "domain": 12}]
        origins = {"198.51.100.10": {50}, "10.5.5.5": {77}}
        report = _exit_report(FP_A, "198.51.100.10")
        summary = run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "10.5.5.5")],
                      origins=origins, weights={}, relays=relays, aroi=aroi)
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"other": 10})
        self.assertEqual(summary["version"], 2)

    def test_legacy_only_resolver_block_is_removed_when_nothing_remains(self):
        """An in-place re-run drops a resolver block that contained only legacy keys."""
        report = _exit_report(FP_A, "198.51.100.10")
        report["results"][0]["resolver"] = {"primary": "local", "public": False, "queries": {"local": 40}}
        run(report, rows=[row("u.bbbbbbbb.tor.exit.validator.1aeo.com", "8.8.8.8")])
        self.assertNotIn("resolver", report["results"][0])
        self.assertEqual(report["metadata"]["resolvers"]["version"], 2)

    def test_rows_are_archived_before_classification(self):
        """Fetched rows are kept when classification raises, and the report file stays unchanged."""
        with tempfile.TemporaryDirectory() as tmp:
            report = make_report()
            path = os.path.join(tmp, "dns_health_x.json")
            with open(path, "w") as handle:
                json.dump(report, handle)
            with mock.patch.object(resolver_stats, "graphql_rows", return_value=ROWS), \
                 mock.patch.object(resolver_stats, "add_resolver_stats", side_effect=RuntimeError("onionoo")), \
                 mock.patch.dict(os.environ, {"DEPLOY_DIR": tmp}):
                with self.assertRaises(RuntimeError):
                    resolver_stats.main(path)
            archive = os.path.join(tmp, "data", "resolver_rows", "dns_health_x.jsonl.gz")
            with gzip.open(archive, "rt", encoding="utf-8") as handle:
                self.assertEqual(json.loads(handle.readline())["sourceIP"], ROWS[0]["sourceIP"])
            with open(path) as handle:
                self.assertEqual(json.load(handle), report)

    def test_version1_history_is_not_carried(self):
        """A v1 report is skipped entirely: carrying its public part without its 'local' would bias shares."""
        previous = _exit_report(FP_A, "203.0.113.5")
        previous["metadata"]["timestamp"] = "2026-10-08T07:26:08.878754Z"  # 84 h earlier
        previous["metadata"]["resolvers"] = {"version": 1}
        previous["results"][0]["resolver"] = {"queries": {"local": 100, "google": 20}}
        report = _exit_report(FP_A, "203.0.113.5")
        run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "8.8.8.8")], previous=previous)
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"google": 10})
        # a stray legacy key inside a v2 block is dropped, the rest is carried
        previous["metadata"]["resolvers"] = {"version": 2}
        report = _exit_report(FP_A, "203.0.113.5")
        run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "8.8.8.8")], previous=previous)
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"google": 20.0})

    def test_newest_previous_wins_whatever_the_caller_order(self):
        """add_resolver_stats sorts earlier reports itself; the newest one with the exit wins."""
        older = make_report(timestamp="2026-10-04T19:26:08Z")
        older["metadata"]["resolvers"] = {"version": 2}
        older["results"][2]["resolver"] = {"queries": {"google": 400}}
        newer = make_report(timestamp="2026-10-11T07:26:08Z")
        newer["metadata"]["resolvers"] = {"version": 2}
        newer["results"][2]["resolver"] = {"queries": {"local_24": 300}}
        for order in ([newer, older], [older, newer]):
            report = make_report()
            run(report, previous=order)
            self.assertEqual(report["results"][2]["resolver"]["primary"], "local_24")

    def test_rerun_drops_stale_blocks_with_mixed_keys(self):
        """An exit with nothing new or carried loses any existing block, even a mixed v1 one."""
        report = _exit_report(FP_A, "198.51.100.10")
        report["results"][0]["resolver"] = {"primary": "local", "public": False,
                                            "queries": {"local": 90, "google": 10}}
        run(report, rows=[row("u.bbbbbbbb.tor.exit.validator.1aeo.com", "8.8.8.8")])
        self.assertNotIn("resolver", report["results"][0])
        self.assertAlmostEqual(sum(report["metadata"]["resolvers"]["share_pct"].values()), 0.0)

    def test_local_tiers_compete_as_one_group_for_primary(self):
        """Split local traffic is not out-voted by a smaller public share (as v1 'local' was not)."""
        self.assertEqual(resolver_stats.primary_of(
            {"cloudflare": 31, "local_24": 43, "local_as": 32, "quad9": 46}), "local_24")
        self.assertEqual(resolver_stats.primary_of({"cloudflare": 53, "local_22": 35, "local_24": 24}), "local_22")
        self.assertEqual(resolver_stats.primary_of({"google": 60, "local_24": 20, "local_22": 15}), "google")
        self.assertEqual(resolver_stats.primary_of({"local_24": 10, "google": 5}), None)    # below LABEL

    def test_operator_is_checked_before_unknown(self):
        """A group relay address is local_operator even when its own origin-AS lookup fails."""
        relays = [_relay(FP_A, ["198.51.100.10:9001"]), _relay(FP_B, ["198.18.0.77:9001"])]
        aroi = [{"fingerprint": fp, "valid": True, "domain": "ops-net.example"} for fp in (FP_A, FP_B)]
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "198.18.0.77")] * 3 + \
               [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "198.51.100.10")] * 4
        report = _exit_report(FP_A, "198.51.100.10")
        run(report, rows=rows, origins={"198.51.100.10": {50}}, weights={}, relays=relays, aroi=aroi)
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"local_24": 40, "local_operator": 30})

    def test_contact_domains_never_name_the_operator(self):
        """A resolver confirmed under a ContactInfo domain is not local_operator, with or without AROI."""
        relays = [_relay(FP_A, ["198.51.100.10:9001"], contact="url:https://ops.example"),
                  _relay(FP_B, ["198.51.100.200:9001"], contact="url:https://unrelated.example")]
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "192.0.2.50")] * 3
        origins = {"192.0.2.50": {77}, "198.51.100.10": {50}}

        def names(ip):
            """192.0.2.50 forward-confirms under the contact domains."""
            return {"dns.unrelated.example", "dns.ops.example"} if ip == "192.0.2.50" else set()
        for aroi in ([], [{"fingerprint": FP_A, "valid": True, "domain": "validated-ops.example"},
                          {"fingerprint": FP_B, "valid": True, "domain": "validated-ops.example"}]):
            report = _exit_report(FP_A, "198.51.100.10")
            run(report, rows=rows, origins=origins, weights={}, relays=relays, aroi=aroi, fcrdns=names)
            self.assertEqual(report["results"][0]["resolver"]["queries"], {"other": 30})

    def test_reverse_dns_only_for_ips_that_can_match_and_capped(self):
        """No operator domain, no reverse DNS; the heaviest candidates first, at most FCRDNS_MAX."""
        calls = []

        def fcrdns(ip):
            """Record which resolver IPs get a reverse-DNS check."""
            calls.append(ip)
            return set()
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "192.0.2.50")] * 3 + \
               [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "192.0.2.51")]
        origins = {"192.0.2.50": {77}, "192.0.2.51": {77}, "198.51.100.10": {50}}
        report = _exit_report(FP_A, "198.51.100.10")
        run(report, rows=rows, origins=origins, weights={}, relays=[_relay(FP_A, ["198.51.100.10:9001"])],
            fcrdns=fcrdns)
        self.assertEqual(calls, [])                                  # exit has no operator domain
        aroi = [{"fingerprint": FP_A, "valid": True, "domain": "ops-net.example"}]
        with mock.patch.object(resolver_stats, "FCRDNS_MAX", 1):
            run(_exit_report(FP_A, "198.51.100.10"), rows=rows, origins=origins, weights={},
                relays=[_relay(FP_A, ["198.51.100.10:9001"])], aroi=aroi, fcrdns=fcrdns)
        self.assertEqual(calls, ["192.0.2.50"])                      # heaviest only, capped at 1

    def test_archive_rows_writes_only_sampled_fields(self):
        """The private archive keeps the four analytics fields and nothing else."""
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"DEPLOY_DIR": tmp, "CF_ANALYTICS_TOKEN": "should-not-appear"}):
                resolver_stats.archive_rows(os.path.join(tmp, "dns_health_x.json"), [
                    {"datetime": "2026-10-11T19:10:00Z", "queryName": "q.example", "sourceIP": "8.8.8.8",
                     "sampleInterval": 10, "extra": "drop-me"}])
            path = os.path.join(tmp, "data", "resolver_rows", "dns_health_x.jsonl.gz")
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                saved = json.loads(handle.readline())
            self.assertEqual(saved, {"datetime": "2026-10-11T19:10:00Z", "queryName": "q.example",
                                     "sourceIP": "8.8.8.8", "sampleInterval": 10})
            with open(path, "rb") as raw:
                self.assertNotIn(b"should-not-appear", raw.read())


class TestGraphqlPaging(unittest.TestCase):

    def test_pages_without_dropping_or_repeating_boundary_rows(self):
        """Paging re-reads the boundary second whole."""
        data = [{"datetime": f"2026-10-11T19:10:0{s}Z", "queryName": f"q{i}.x", "sourceIP": "8.8.8.8",
                 "sampleInterval": 10} for i, s in enumerate([0, 1, 1, 2, 2, 3, 4, 4, 5])]
        calls = []

        def fake_urlopen(req, timeout=None):
            """Serve the filtered data set, PAGE_SIZE rows at a time, like the GraphQL API."""
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
             mock.patch.object(resolver_stats, "GRAPHQL_OPENER", types.SimpleNamespace(open=fake_urlopen)), \
             mock.patch.dict(os.environ, {"CF_ZONE_ID": "zone", "CF_ANALYTICS_TOKEN": "tok"}):
            rows = graphql_rows("2026-10-11T19:10:00Z", "2026-10-11T19:10:09Z", "x")
        self.assertEqual([r["queryName"] for r in rows], [r["queryName"] for r in data])
        self.assertTrue(all(c["queryName_like"] == "%.x" for c in calls))

    def test_bad_token_rejected_without_echo(self):
        """A malformed token fails with a message that never contains it."""
        with mock.patch.dict(os.environ, {"CF_ZONE_ID": "zone", "CF_ANALYTICS_TOKEN": "\u201csecret-value\u201d"}):
            with self.assertRaises(RuntimeError) as ctx:
                graphql_rows("2026-10-11T19:10:00Z", "2026-10-11T19:10:09Z", "x")
        self.assertNotIn("secret-value", str(ctx.exception))

    def test_full_boundary_second_raises(self):
        """A boundary second with PAGE_SIZE+ rows cannot be paged losslessly: raise."""
        data = [{"datetime": "2026-10-11T19:10:00Z", "queryName": f"q{i}.x", "sourceIP": "8.8.8.8",
                 "sampleInterval": 10} for i in range(5)]

        def fake_urlopen(req, timeout=None):
            """Every request returns the first PAGE_SIZE rows of the single busy second."""
            out = {"data": {"viewer": {"zones": [{"dnsAnalyticsAdaptive": data[:resolver_stats.PAGE_SIZE]}]}}}
            return io.BytesIO(json.dumps(out).encode())
        with mock.patch.object(resolver_stats, "PAGE_SIZE", 3), \
             mock.patch.object(resolver_stats, "GRAPHQL_OPENER", types.SimpleNamespace(open=fake_urlopen)), \
             mock.patch.dict(os.environ, {"CF_ZONE_ID": "zone", "CF_ANALYTICS_TOKEN": "tok"}):
            with self.assertRaises(RuntimeError):
                graphql_rows("2026-10-11T19:10:00Z", "2026-10-11T19:10:09Z", "x")

    def test_graphql_errors_raise(self):
        """GraphQL errors raise instead of returning partial data."""
        err = io.BytesIO(json.dumps({"data": None, "errors": [
            {"message": "bad filter", "path": ["viewer"], "extensions": {"zoneTag": "secret-zone"}}]}).encode())
        with mock.patch.object(resolver_stats, "GRAPHQL_OPENER", mock.Mock(open=mock.Mock(return_value=err))), \
             mock.patch.dict(os.environ, {"CF_ZONE_ID": "zone", "CF_ANALYTICS_TOKEN": "tok"}):
            with self.assertRaises(RuntimeError) as ctx:
                graphql_rows("2026-10-11T19:10:00Z", "2026-10-11T19:10:09Z", "x")
        self.assertEqual(str(ctx.exception), "GraphQL error: bad filter")  # message only, no error objects

    def test_redirect_is_refused_and_token_not_forwarded(self):
        """A 3xx from the GraphQL endpoint fails; the redirect target never sees the token."""
        import http.server
        import threading
        seen = []

        class Target(http.server.BaseHTTPRequestHandler):
            """Records the Authorization header of any request it receives."""
            def do_POST(self):
                """Record and answer."""
                seen.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"data": {"viewer": {"zones": [{"dnsAnalyticsAdaptive": []}]}}}')
            do_GET = do_POST

            def log_message(self, *args):
                """Quiet."""

        target = http.server.HTTPServer(("127.0.0.1", 0), Target)

        class Redirect(http.server.BaseHTTPRequestHandler):
            """Answers every POST with a 302 to the target server."""
            def do_POST(self):
                """Redirect."""
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{target.server_port}/steal")
                self.end_headers()

            def log_message(self, *args):
                """Quiet."""

        origin = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
        for srv in (target, origin):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with mock.patch.object(resolver_stats, "GRAPHQL", f"http://127.0.0.1:{origin.server_port}/graphql"), \
                 mock.patch.dict(os.environ, {"CF_ZONE_ID": "zone", "CF_ANALYTICS_TOKEN": "tok"}), \
                 self.assertRaises(urllib.error.HTTPError) as ctx:
                graphql_rows("2026-10-11T19:10:00Z", "2026-10-11T19:10:09Z", "x")
            self.assertEqual(ctx.exception.code, 302)        # the 3xx itself surfaces, nothing followed
        finally:
            target.shutdown()
            origin.shutdown()
        self.assertEqual(seen, [])


class TestLookups(unittest.TestCase):

    def origin(self, ip, *answers):
        """origin_asns(ip) against a fake dns.resolver returning the given Team Cymru records."""
        queried = []

        def resolve(name, rdtype, lifetime=None):
            """Record the query name; answer with the canned TXT records or time out."""
            queried.append(name)
            if not answers:
                raise OSError("timeout")
            return [types.SimpleNamespace(to_text=lambda a=a: '"%s | US | arin |"' % a) for a in answers]
        fake = types.ModuleType("dns")
        fake.resolver = types.SimpleNamespace(resolve=resolve)
        with mock.patch.dict(sys.modules, {"dns": fake, "dns.resolver": fake.resolver}):
            return origin_asns(ip), queried

    def test_ipv4_query_name(self):
        """IPv4 origin lookup queries <reversed-ip>.origin.asn.cymru.com."""
        self.assertEqual(self.origin("8.8.4.4", "15169 | 8.8.4.0/24"), ({15169}, ["4.4.8.8.origin.asn.cymru.com"]))

    def test_ipv6_query_name_for_shortened_address(self):
        """IPv6 origin lookup uses all 32 nibbles, even for shortened addresses."""
        asns, (name,) = self.origin("2a06:98c1:53::", "13335 | 2a06:98c0::/29")
        self.assertEqual(asns, {13335})
        self.assertTrue(name.endswith(".1.c.8.9.6.0.a.2.origin6.asn.cymru.com"))
        self.assertEqual(len(name.split(".")), 32 + 4)

    def test_most_specific_prefix_wins_and_failure_is_none(self):
        """Most specific covering prefix wins; lookup failure gives None."""
        self.assertEqual(self.origin("192.0.2.1", "64500 | 192.0.0.0/16", "42 715 | 192.0.2.0/24")[0], {42, 715})
        self.assertEqual(self.origin("192.0.2.1", "42 | 192.0.2.0/24", "64500 | 192.0.0.0/16")[0], {42})
        self.assertIsNone(self.origin("192.0.2.1")[0])

    def test_published_ranges_and_fallbacks(self):
        """Google JSON, then TXT; Cloudflare API, then the pinned snapshot."""
        google = {"prefixes": [{"ipv4Prefix": f"34.64.{i}.0/24", "service": "Google Public DNS"} for i in range(150)]
                              + [{"ipv6Prefix": "2001:4860:4860::/48", "service": "Google Public DNS"}]}
        cloudflare = {"result": {"ipv4_cidrs": ["172.64.0.0/13"], "ipv6_cidrs": ["2400:cb00::/32"]}}

        def ok(url, timeout=None):
            """Both published lists reachable."""
            return io.BytesIO(json.dumps(google if "gstatic" in url else cloudflare).encode())
        with mock.patch.object(resolver_stats.urllib.request, "urlopen", ok):
            r = published_ranges()
        self.assertEqual((len(r["google"]), [str(n) for n in r["cloudflare"]]), (151, ["172.64.0.0/13", "2400:cb00::/32"]))

        def down(url, timeout=None):
            """Both published lists unreachable."""
            raise OSError("unreachable")
        txt = [types.SimpleNamespace(strings=[f"34.64.{i}.0/24 icn ".encode() for i in range(120)])]
        fake = types.ModuleType("dns")
        fake.resolver = types.SimpleNamespace(resolve=lambda name, rdtype, lifetime=None: txt)
        with mock.patch.object(resolver_stats.urllib.request, "urlopen", down), \
             mock.patch.dict(sys.modules, {"dns": fake, "dns.resolver": fake.resolver}):
            r = published_ranges()                       # Google from the TXT record, Cloudflare snapshot
        self.assertEqual((len(r["google"]), len(r["cloudflare"])), (120, len(resolver_stats.CLOUDFLARE_SNAPSHOT)))

    def test_directory_fetch_refuses_redirects(self):
        """Onionoo and AROI fetches do not follow a 3xx."""
        import http.server
        import threading

        class Redirect(http.server.BaseHTTPRequestHandler):
            """Answers with a 302 and no body."""

            def do_GET(self):
                """Redirect."""
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1/other")
                self.end_headers()

            def log_message(self, *args):
                """Quiet."""

        origin = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(RuntimeError) as ctx:
                resolver_stats.fetch_json(f"http://127.0.0.1:{origin.server_port}/details", timeout=5)
            self.assertIn("refusing redirect", str(ctx.exception))
        finally:
            origin.shutdown()

    def test_fcrdns_keeps_only_forward_confirmed_names(self):
        """A PTR counts only when its A/AAAA record contains the resolver address."""
        state = {"forward": "192.0.2.50"}

        def resolve(name, rdtype, lifetime=None):
            """PTR dns.example.org, whose A record is state['forward']."""
            if rdtype == "PTR":
                return [types.SimpleNamespace(to_text=lambda: "dns.example.org.")]
            if rdtype == "A" and name == "dns.example.org":
                return [types.SimpleNamespace(to_text=lambda: state["forward"])]
            raise OSError("no such record")

        fake = types.ModuleType("dns")
        fake.resolver = types.SimpleNamespace(resolve=resolve)
        with mock.patch.dict(sys.modules, {"dns": fake, "dns.resolver": fake.resolver}):
            self.assertEqual(resolver_stats.fcrdns_names("192.0.2.50"), {"dns.example.org"})
            state["forward"] = "192.0.2.51"
            self.assertEqual(resolver_stats.fcrdns_names("192.0.2.50"), set())
        def fail(*args, **kwargs):
            """DNS lookup timed out."""
            raise OSError("timeout")

        fake.resolver = types.SimpleNamespace(resolve=fail)
        with mock.patch.dict(sys.modules, {"dns": fake, "dns.resolver": fake.resolver}):
            self.assertEqual(resolver_stats.fcrdns_names("192.0.2.50"), set())

    def test_fcrdns_candidates_include_names_registered_as_the_operator(self):
        """A PTR registered in an operator's name is forward-checked like one under a domain."""
        forward = []

        def resolve(name, rdtype, lifetime=None):
            """PTRs at a hoster; record every forward lookup."""
            if rdtype == "PTR":
                names = ["artikel10.in-berlin.de.", "artikel10x.in-berlin.de.", "web1.in-berlin.de.",
                         "artikel10.attacker.test."]
                return [types.SimpleNamespace(to_text=lambda n=n: n) for n in names]
            forward.append(name)
            return [types.SimpleNamespace(to_text=lambda: "217.197.91.153")]

        fake = types.ModuleType("dns")
        fake.resolver = types.SimpleNamespace(resolve=resolve)
        with mock.patch.dict(sys.modules, {"dns": fake, "dns.resolver": fake.resolver}):
            self.assertEqual(resolver_stats.fcrdns_names("217.197.91.153", set(), {"artikel10"}, SUFFIXES),
                             {"artikel10.in-berlin.de"})
        self.assertEqual(forward, ["artikel10.in-berlin.de"])

    def test_at_most_one_forward_lookup_per_ip_matches_only_by_name(self):
        """PTRs registered in an operator's name elsewhere cost one forward lookup, not FCRDNS_NAMES."""
        forward = []

        def resolve(name, rdtype, lifetime=None):
            """Five names registered as artikel10 under other suffixes plus one under the operator domain."""
            if rdtype == "PTR":
                names = ["artikel10.%s." % suffix for suffix in ("se", "net", "de", "com", "hopto.org")]
                names.append("ns.artikel10.org.")
                return [types.SimpleNamespace(to_text=lambda n=n: n) for n in names]
            forward.append(name)
            raise OSError("timeout")

        fake = types.ModuleType("dns")
        fake.resolver = types.SimpleNamespace(resolve=resolve)
        with mock.patch.dict(sys.modules, {"dns": fake, "dns.resolver": fake.resolver}):
            resolver_stats.fcrdns_names("192.0.2.50", {"artikel10.org"}, {"artikel10"}, SUFFIXES)
        self.assertEqual(forward, ["ns.artikel10.org", "artikel10.com"])

    def test_operator_name_reaches_reverse_dns_in_production_path(self):
        """With fcrdns=None, add_resolver_stats passes operator names to the real reverse-DNS check."""
        forward = []

        def resolve(name, rdtype, lifetime=None):
            """PTR artikel10.in-berlin.de, forward-confirmed."""
            if rdtype == "PTR":
                return [types.SimpleNamespace(to_text=lambda: "artikel10.in-berlin.de.")]
            forward.append(name)
            return [types.SimpleNamespace(to_text=lambda: "217.197.91.153")]

        fake = types.ModuleType("dns")
        fake.resolver = types.SimpleNamespace(resolve=resolve)
        report = _exit_report(FP_A, "198.51.100.10")
        with mock.patch.dict(sys.modules, {"dns": fake, "dns.resolver": fake.resolver}):
            add_resolver_stats(report, [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "217.197.91.153")],
                               None, ranges=RANGES, origin={"198.51.100.10": {60729}, "217.197.91.153": {29670}}.get,
                               weights={}, relays=[_relay(FP_A, ["198.51.100.10:9001"])],
                               aroi=[{"fingerprint": FP_A, "valid": True, "domain": "artikel10.org"}],
                               fcrdns=None, suffixes=SUFFIXES)
        self.assertEqual(forward, ["artikel10.in-berlin.de"])
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"local_operator": 10})

    def test_fcrdns_forward_checks_only_candidate_names(self):
        """With domains, PTR names outside them are never forward-resolved; at most FCRDNS_NAMES are."""
        forward = []

        def resolve(name, rdtype, lifetime=None):
            """Many PTR names; record every forward lookup."""
            if rdtype == "PTR":
                names = ["x%d.attacker.test." % i for i in range(50)] + ["dns.ops.example."]
                return [types.SimpleNamespace(to_text=lambda n=n: n) for n in names]
            forward.append(name)
            return [types.SimpleNamespace(to_text=lambda: "192.0.2.50")]

        fake = types.ModuleType("dns")
        fake.resolver = types.SimpleNamespace(resolve=resolve)
        with mock.patch.dict(sys.modules, {"dns": fake, "dns.resolver": fake.resolver}):
            self.assertEqual(resolver_stats.fcrdns_names("192.0.2.50", {"ops.example"}), {"dns.ops.example"})
            self.assertEqual(forward, ["dns.ops.example"])
            forward.clear()
            resolver_stats.fcrdns_names("192.0.2.50")
            self.assertEqual(len(forward), resolver_stats.FCRDNS_NAMES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
