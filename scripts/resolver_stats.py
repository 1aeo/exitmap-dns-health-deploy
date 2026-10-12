#!/usr/bin/env python3
"""
Estimate which DNS resolver each exit uses, from Cloudflare's sampled DNS analytics.

Usage: resolver_stats.py REPORT_JSON [PREVIOUS_REPORT_JSON]

Fetches the validator zone's queries for the scan window from the GraphQL
dnsAnalyticsAdaptive dataset (env CF_ANALYTICS_TOKEN, CF_ZONE_ID), maps each query
to its exit via the fp8 label, classifies the querying resolver by origin AS and
adds results[].resolver plus metadata.resolvers to REPORT_JSON in place.
Per-exit counts are sample-weighted estimates carried forward from the previous
report with a 3.5-day half-life. On any error the report is left unchanged.
"""

import glob, ipaddress, json, os, sys, urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

PUBLIC = {15169: "google", 396982: "google", 13335: "cloudflare", 19281: "quad9",
          42: "quad9", 715: "quad9", 36692: "opendns"}
PROVIDERS = ("google", "cloudflare", "quad9", "opendns")
ONIONOO = ("https://onionoo.torproject.org/details?type=relay&running=true&flag=Exit"
           "&fields=fingerprint,exit_probability")
GRAPHQL = "https://api.cloudflare.com/client/v4/graphql"
QUERY = """query($z:String!,$f:ZoneDnsAnalyticsAdaptiveFilter_InputObject!){viewer{zones(filter:{zoneTag:$z}){
dnsAnalyticsAdaptive(filter:$f,limit:10000,orderBy:[datetime_ASC]){datetime queryName sourceIP sampleInterval}}}}"""
PAGE_SIZE = 10000
WINDOW_PAD = 300     # seconds around the scan's first/last result
HALF_LIFE_H = 84     # carry-forward half-life (3.5 days)
SEEN, LABEL = 5, 25  # decayed estimated queries to count an exit as seen / to label it


def epoch(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def graphql_rows(start, end, suffix):
    """All sampled validator queries in [start, end], paging on datetime."""
    def page(window):
        flt = {"datetime_leq": end, "queryName_like": "%." + suffix, **window}
        body = json.dumps({"query": QUERY, "variables": {"z": os.environ["CF_ZONE_ID"], "f": flt}}).encode()
        req = urllib.request.Request(GRAPHQL, body, {"Authorization": "Bearer " + os.environ["CF_ANALYTICS_TOKEN"],
                                                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.load(resp)
        if data.get("errors"):
            raise RuntimeError(f"GraphQL error: {data['errors']}")
        return data["data"]["viewer"]["zones"][0]["dnsAnalyticsAdaptive"]
    rows, window = [], {"datetime_geq": start}
    while True:
        batch = page(window)
        if len(batch) < PAGE_SIZE:
            return rows + batch
        last = batch[-1]["datetime"]  # re-read the boundary second whole: no dropped or repeated rows
        rows += [r for r in batch if r["datetime"] != last] + page({"datetime_geq": last, "datetime_leq": last})
        window = {"datetime_gt": last}


def asn_provider(ip):
    """Resolver IP -> provider via Team Cymru origin ASN ('other', or 'unknown' if the lookup fails)."""
    import dns.resolver
    try:
        addr = ipaddress.ip_address(ip)
        zone = "origin.asn.cymru.com" if addr.version == 4 else "origin6.asn.cymru.com"
        name = addr.reverse_pointer.rsplit(".", 2)[0] + "." + zone
        txt = dns.resolver.resolve(name, "TXT", lifetime=10)[0].to_text().strip('"')
        asns = {int(a) for a in txt.split("|")[0].split()}
    except Exception:
        return "unknown"
    return next((PUBLIC[a] for a in asns if a in PUBLIC), "other")


def exit_probabilities():
    try:
        with urllib.request.urlopen(ONIONOO, timeout=60) as resp:
            return {r["fingerprint"]: r.get("exit_probability") or 0.0 for r in json.load(resp)["relays"]}
    except Exception as e:
        print(f"Onionoo unavailable ({e}); resolver shares unweighted", file=sys.stderr)
        return {}


def load_previous(path, current):
    """Newest report with resolver data: PREVIOUS_REPORT_JSON, else recent dns_health_*.json beside it."""
    if not path:
        return None
    recent = sorted(glob.glob(os.path.join(os.path.dirname(path), "dns_health_*.json")), reverse=True)[:10]
    for p in [path] + recent:
        if os.path.isfile(p) and not os.path.samefile(p, current):
            try:
                with open(p) as f:
                    prev = json.load(f)
            except (OSError, ValueError):
                continue
            if prev.get("metadata", {}).get("resolvers"):
                return prev
    return None


def scan_window(report):
    ts = [r["timestamp"] for r in report["results"] if r.get("timestamp")]
    return iso(min(ts) - WINDOW_PAD), iso(max(ts) + WINDOW_PAD)


def add_resolver_stats(report, rows, previous=None, lookup=asn_provider, weights=None):
    results = report["results"]
    suffix = "." + os.environ.get("DNS_WILDCARD_DOMAIN", "tor.exit.validator.1aeo.com").lower().strip(".")
    by_fp8 = {}
    for r in results:
        fp8 = (r.get("exit_fingerprint") or "")[:8].lower()
        by_fp8[fp8] = None if fp8 in by_fp8 else r  # drop ambiguous prefixes
    est, n_rows, n_est = defaultdict(Counter), 0, 0
    for row in rows:
        name = row["queryName"].lower().rstrip(".")
        if name.endswith(suffix):
            n_rows, n_est = n_rows + 1, n_est + row["sampleInterval"]
            r = by_fp8.get(name[:-len(suffix)].rsplit(".", 1)[-1])
            if r:
                est[r["exit_fingerprint"]][row["sourceIP"]] += row["sampleInterval"]
    if not n_rows:
        raise RuntimeError("no validator queries in the scan window")
    ips = sorted({ip for c in est.values() for ip in c})
    with ThreadPoolExecutor(32) as pool:
        provider = dict(zip(ips, pool.map(lookup, ips)))
    decay, carried = 0.0, {}
    if previous:
        hours = (epoch(report["metadata"]["timestamp"]) - epoch(previous["metadata"]["timestamp"])) / 3600
        decay = 0.5 ** (max(hours, 0.0) / HALF_LIFE_H)
        carried = {p.get("exit_fingerprint"): p["resolver"].get("queries") or {} for p in previous["results"] if p.get("resolver")}
    for r in results:
        q = Counter({k: v * decay for k, v in carried.get(r.get("exit_fingerprint"), {}).items()})
        for ip, n in est.get(r.get("exit_fingerprint"), {}).items():
            q[provider[ip]] += n
        q = {k: round(v, 2) for k, v in sorted(q.items()) if v >= 0.01}
        if q:
            known = {k: v for k, v in q.items() if k != "unknown"}
            labelled = sum(known.values()) >= LABEL
            r["resolver"] = {"primary": max(known, key=known.get) if labelled else None,
                             "public": any(k in PROVIDERS for k in known) if labelled else None,
                             "queries": q}
    weights = exit_probabilities() if weights is None else weights
    ok = [r for r in results if r.get("status") == "success"]
    share, wsum, seen, labelled, using_public = Counter(), 0.0, 0, 0, 0
    for r in ok:
        known = {k: v for k, v in r.get("resolver", {}).get("queries", {}).items() if k != "unknown"}
        total = sum(known.values())
        if total < SEEN:
            continue
        seen += 1
        labelled += total >= LABEL
        using_public += r["resolver"]["public"] is True
        w = weights.get(r.get("exit_fingerprint"), 0.0) if weights else 1.0
        wsum += w
        for k, v in known.items():
            share[k] += w * v / total
    pct = {p: round(100 * share[p] / wsum, 2) if wsum else 0.0 for p in PROVIDERS}
    pct["all"] = round(sum(pct.values()), 2)
    start, end = scan_window(report)
    report["metadata"]["resolvers"] = {
        "version": 1, "source": "cloudflare-dns-analytics-sampled", "window": {"start": start, "end": end},
        "rows": n_rows, "est_queries": n_est, "half_life_hours": HALF_LIFE_H,
        "thresholds": {"seen": SEEN, "label": LABEL}, "weighted": bool(weights),
        "exits_total": len(ok), "exits_covered": seen, "exits_labelled": labelled,
        "exits_using_public": using_public, "public_share_pct": pct}
    return report["metadata"]["resolvers"]


def main(report_path, previous_path=None):
    with open(report_path) as f:
        report = json.load(f)
    start, end = scan_window(report)
    suffix = os.environ.get("DNS_WILDCARD_DOMAIN", "tor.exit.validator.1aeo.com").lower().strip(".")
    summary = add_resolver_stats(report, graphql_rows(start, end, suffix), load_previous(previous_path, report_path))
    with open(report_path + ".tmp", "w") as f:
        json.dump(report, f)
    os.replace(report_path + ".tmp", report_path)
    print("Resolver stats:", json.dumps(summary))


if __name__ == "__main__":
    try:
        main(*sys.argv[1:3])
    except Exception as e:
        print(f"Resolver stats failed: {e!r}", file=sys.stderr)
        sys.exit(1)
