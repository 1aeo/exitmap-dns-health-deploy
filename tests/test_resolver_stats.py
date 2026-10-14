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
        aroi=(), aroi_available=True, fcrdns=None):
    """add_resolver_stats with fixed ranges, AS data and exit weights (no network)."""
    return add_resolver_stats(report, rows, previous, ranges=RANGES, origin=origins.get, weights=weights,
                              relays=list(relays), aroi=list(aroi), aroi_available=aroi_available,
                              fcrdns=fcrdns or (lambda ip: set()))


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
        self.assertEqual(s["operator_sources"], {"onionoo": True, "aroi": True})
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
        """Only strictly older reports with resolver data, newest first."""
        with tempfile.TemporaryDirectory() as d:
            def write(name, ts, with_data):
                """Write a report into the temp dir and return its path."""
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
        """An exit absent from the newest report keeps its older counts."""
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
        """A previous report that is not older (e.g. a re-run) is refused."""
        same = make_report()
        same["metadata"]["resolvers"] = {"version": 1}
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
        """More than half the new queries without AS data: abort; at half: publish."""
        report = make_report()
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "192.0.2.10")] * 3 + \
               [row("u.bbbbbbbb.tor.exit.validator.1aeo.com", "8.8.8.8")]  # list-matched: needs no AS lookup
        with self.assertRaises(RuntimeError):
            run(report, rows=rows, origins={})                  # 30 of 40 estimated queries unknown
        self.assertEqual(report, make_report())
        run(report, rows=rows[2:], origins={})                  # 10 of 20 unknown: at the limit, still published
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"unknown": 10})

    def test_unknown_counts_and_can_be_primary(self):
        """Queries without AS data still count toward shares; an 'unknown' primary has public=None."""
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "198.51.100.1")] * 3 + \
               [row("u.bbbbbbbb.tor.exit.validator.1aeo.com", "8.8.8.8")] * 4
        report = make_report()
        s = run(report, rows=rows, weights={})
        self.assertEqual(report["results"][0]["resolver"], {"primary": "unknown", "public": None,
                                                           "queries": {"unknown": 30}})
        self.assertEqual((s["share_pct"]["unknown"], s["share_pct"]["google"]), (50.0, 50.0))
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
        run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "192.0.2.20")] * 3, origins={})
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"local_24": 30})

    def test_operator_by_address_prefix_and_confirmed_name(self):
        """Family address, footprint /24 and /48, and FCrDNS match; a same-AS hit stays local_as."""
        contact = "email:ops[]example.net url:https://www.example.net/exit"
        family = ["$" + FP_A, FP_B, FP_C, FP_D]
        relays = [
            _relay(FP_A, ["198.51.100.10:9001"], ["198.51.100.10"], family, contact),
            _relay(FP_B, ["10.8.8.8:9001"], family=family),
            _relay(FP_C, ["10.7.7.8:9001", "[2001:db8:abcd::1]:9001"], family=family),
        ]
        aroi = [{"fingerprint": FP_A, "valid": True, "domain": "Example.NET"},
                {"fingerprint": FP_D, "valid": False, "domain": "example.net"}]
        origins = {"198.51.100.10": {50}, "10.8.8.8": {77}, "10.7.7.9": {77}, "10.1.2.3": {50},
                   "192.0.2.50": {77}, "192.0.2.51": {77}, "2001:db8:abcd:99::5": {77}}
        confirmed = {"192.0.2.50": {"dns.example.net"}, "192.0.2.51": set(),
                     "10.8.8.8": set(), "10.7.7.9": set(), "10.1.2.3": set(), "2001:db8:abcd:99::5": set()}
        rows = [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", ip) for ip in
                ("10.8.8.8", "10.7.7.9", "2001:db8:abcd:99::5", "192.0.2.50", "192.0.2.51", "10.1.2.3")]
        # 10.1.2.3 shares the exit's AS, so it is local_as even though a family relay could sit there.
        relays.append(_relay(FP_D, ["10.1.2.3:9001"], family=family))
        report = _exit_report(FP_A, "198.51.100.10")
        summary = run(report, rows=rows, origins=origins, weights={}, relays=relays, aroi=aroi,
                      fcrdns=confirmed.get)
        queries = report["results"][0]["resolver"]["queries"]
        self.assertEqual(queries, {"local_as": 10, "local_operator": 40, "other": 10})
        self.assertEqual(summary["operator_signals"], {"address": 10, "prefix": 20, "fcrdns": 10})
        self.assertEqual((report["results"][0]["resolver"]["primary"],
                          report["results"][0]["resolver"]["public"]), ("local_operator", False))

    def test_aroi_groups_operators_and_contact_is_only_a_fallback(self):
        """A shared validated domain groups relays; the same contact does not when a domain exists."""
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
        # B shares the AROI domain. C only shares contact text, which is not used once AROI matched.
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"local_operator": 10, "other": 10})

    def test_contact_fallback_when_aroi_has_no_domain_for_the_exit(self):
        """Identical normalized ContactInfo groups relays that have no validated AROI domain."""
        relays = [
            _relay(FP_A, ["198.51.100.10:9001"], contact="Email:  Ops []  Example.NET"),
            _relay(FP_B, ["10.5.5.5:9001"], contact="email: ops [] example.net"),
        ]
        origins = {"198.51.100.10": {50}, "10.5.5.5": {77}}
        report = _exit_report(FP_A, "198.51.100.10")
        run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "10.5.5.5")],
            origins=origins, weights={}, relays=relays, aroi=[])
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"local_operator": 10})
        self.assertEqual(resolver_stats.contact_domains("email:ops[]Example.NET url:https://www.Example.NET/a"),
                         {"example.net"})

    def test_aroi_outage_continues_and_onionoo_outage_leaves_the_report(self):
        """AROI failing omits that source; Onionoo failing raises and does not publish."""
        relays = [
            _relay(FP_A, ["198.51.100.10:9001"], contact="email:ops[]example.net"),
            _relay(FP_B, ["10.5.5.5:9001"], contact="email:ops[]example.net"),
        ]
        origins = {"198.51.100.10": {50}, "10.5.5.5": {77}}
        report = _exit_report(FP_A, "198.51.100.10")
        with mock.patch.object(resolver_stats, "fetch_aroi", return_value=None):
            summary = add_resolver_stats(
                report, [row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "10.5.5.5")],
                ranges=RANGES, origin=origins.get, weights={}, relays=relays, fcrdns=lambda ip: set())
        self.assertEqual(summary["operator_sources"], {"onionoo": True, "aroi": False})
        self.assertEqual(summary["version"], 2)
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"local_operator": 10})

        untouched = make_report()
        with mock.patch.object(resolver_stats, "fetch_onionoo", side_effect=RuntimeError("down")):
            with self.assertRaises(RuntimeError):
                add_resolver_stats(untouched, ROWS, ranges=RANGES, origin=ORIGINS.get, weights=WEIGHTS,
                                   fcrdns=lambda ip: set())
        self.assertEqual(untouched, make_report())

    def test_confirmed_name_must_sit_under_the_operator_domain(self):
        """A PTR like artikel10.in-berlin.de does not match the AROI domain artikel10.org."""
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
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"other": 10})

    def test_legacy_local_counts_are_dropped_on_carry_forward(self):
        """A carried 'local' key from a version-1 report is not a version-2 category."""
        previous = _exit_report(FP_A, "203.0.113.5")
        previous["metadata"]["timestamp"] = "2026-10-08T07:26:08.878754Z"  # 84 h earlier
        previous["metadata"]["resolvers"] = {"version": 1}
        previous["results"][0]["resolver"] = {"queries": {"local": 100, "google": 20}}
        report = _exit_report(FP_A, "203.0.113.5")
        run(report, rows=[row("u.aaaaaaaa.tor.exit.validator.1aeo.com", "8.8.8.8")], previous=previous)
        self.assertEqual(report["results"][0]["resolver"]["queries"], {"google": 20.0})
        self.assertNotIn("local", report["results"][0]["resolver"]["queries"])

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
