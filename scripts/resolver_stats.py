#!/usr/bin/env python3
"""
Estimate which DNS resolver each exit uses, from Cloudflare's sampled DNS analytics.

Usage: resolver_stats.py REPORT_JSON [PREVIOUS_REPORT_JSON]

Fetches the validator zone's queries for the scan window from the GraphQL
dnsAnalyticsAdaptive dataset (env CF_ANALYTICS_TOKEN, CF_ZONE_ID), maps each query
to its exit via the fp8 label, classifies the querying resolver (public service per
the operator's own published egress data, else "local" to the exit's network or "other")
and adds results[].resolver plus metadata.resolvers to REPORT_JSON in place.
Per-exit counts are sample-weighted estimates carried forward from the previous
report with a 3.5-day half-life. On any error the report is left unchanged.
"""

import glob, ipaddress, json, os, re, sys, urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

# Public resolver services. A query counts for one only when its source IP is covered by what
# the operator itself publishes about the addresses its resolver queries authoritative servers
# from (sources checked 2026-10-12). Otherwise the resolver is "local" (same origin AS as the
# exit's address: the operator's or its hoster's resolver), "other", or "unknown" (no AS data).
# Every category counts toward the shares: they all describe resolvers the exits really used.
#
# google: Google's egress list, not Google's ASNs (AS15169/AS396982 also carry Google Cloud VMs,
#   e.g. an exit's own resolver). Public DNS FAQ, https://developers.google.com/speed/public-dns/faq#locations :
#   "Google publishes a list of the IP address ranges Google Public DNS may use to query
#   authoritative DNS servers" (JSON below; the same list as DNS TXT locations.publicdns.goog).
GOOGLE_RANGES = "https://www.gstatic.com/ipranges/publicdns.json"
GOOGLE_RANGES_TXT = "locations.publicdns.goog"
# cloudflare: Cloudflare's IP list. 1.1.1.1 FAQ, https://developers.cloudflare.com/1.1.1.1/faq/ :
#   "Authoritative DNS providers may want to allowlist the IP addresses that 1.1.1.1 uses when
#   querying upstream nameservers. The full list of Cloudflare IP addresses is available at
#   https://www.cloudflare.com/ips/" (WARP / Cloudflare One client egress is not in that list).
CLOUDFLARE_RANGES = "https://api.cloudflare.com/client/v4/ips"
CLOUDFLARE_SNAPSHOT = (  # https://www.cloudflare.com/ips/ as of 2026-10-12, used if the fetch fails
    "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 "
    "190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 "
    "104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 "
    "2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32").split()
# ffmuc: Freifunk Muenchen public DNS (dns/dot/doh.ffmuc.net). Its setup page, https://dns-setup.ffmuc.net/
#   ("Verify Setup"), lists what a leak test shows: 5.1.66.0/24, 185.150.99.0/24, 2001:678:e68::/48 and
#   2001:678:ed0::/48. For IPv6 only the infrastructure /64s count: the rest of those /48s are Freifunk
#   client networks (https://github.com/freifunkMUC/site-ffm), not the resolver.
FFMUC_RANGES = ["5.1.66.0/24", "185.150.99.0/24", "2001:678:e68:ff00::/64", "2001:678:ed0:ff00::/64"]
PUBLIC_ASNS = {
    # quad9: Quad9 publishes no egress list. Its FAQ, https://docs.quad9.net/FAQs/#network-providers-dns-leak-tests ,
    #   says leak tests show addresses of "WoodyNet (AKA PCH.net)", whose networks are AS42, AS715 and
    #   AS1288 (ARIN); AS19281 is Quad9's own (its PeeringDB entry https://www.peeringdb.com/net/17212
    #   lists "AS42 - PCH - Global"). Quad9 nodes in other providers' networks (IXPs, partners) are
    #   missed, so this is a lower bound; Quad9's own zone of node names (res<N>.<site>.rrdns.pch.net)
    #   would cover them but takes ~170k lookups to enumerate.
    42: "quad9", 715: "quad9", 1288: "quad9", 19281: "quad9",
    # opendns: Cisco's PeeringDB entry for AS36692, https://www.peeringdb.com/net/854 : "Cisco Umbrella
    #   operates a high-speed anycast recursive DNS network"; resolver sites and subnets:
    #   https://umbrella.cisco.com/why-umbrella/global-network-and-traffic
    36692: "opendns",
}
PROVIDERS = ("google", "cloudflare", "quad9", "opendns", "ffmuc")
CATEGORIES = PROVIDERS + ("local", "other", "unknown")
ONIONOO = ("https://onionoo.torproject.org/details?type=relay&running=true&flag=Exit"
           "&fields=fingerprint,exit_probability")
GRAPHQL = "https://api.cloudflare.com/client/v4/graphql"
QUERY = """query($z:String!,$f:ZoneDnsAnalyticsAdaptiveFilter_InputObject!){viewer{zones(filter:{zoneTag:$z}){
dnsAnalyticsAdaptive(filter:$f,limit:10000,orderBy:[datetime_ASC]){datetime queryName sourceIP sampleInterval}}}}"""
PAGE_SIZE = 10000
WINDOW_PAD = 300     # seconds around the scan's first/last result
HALF_LIFE_H = 84     # carry-forward half-life (3.5 days)
SEEN, LABEL = 5, 25  # decayed estimated queries to count an exit as seen / to label it
FLOOR = 1            # drop a provider once its decayed estimate falls below one query
LOOKBACK = 10        # earlier reports searched for an exit's carried counts
MAX_UNKNOWN = 0.5    # abort if resolver lookups fail for more than this share of new queries


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects, so the Authorization header never follows a 3xx to another URL."""

    def redirect_request(self, *args, **kwargs):
        """Returning None makes urllib raise HTTPError for the 3xx instead of following it."""
        return None


GRAPHQL_OPENER = urllib.request.build_opener(NoRedirect)


def epoch(iso):
    """ISO-8601 UTC timestamp ("...Z" or "+00:00") -> epoch seconds."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def iso(ts):
    """Epoch seconds -> ISO-8601 UTC timestamp in the GraphQL filter format."""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def graphql_rows(start, end, suffix):
    """All sampled validator queries in [start, end], paging on datetime."""
    token = os.environ["CF_ANALYTICS_TOKEN"].strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
        raise RuntimeError("CF_ANALYTICS_TOKEN contains invalid characters (value not shown)")

    def page(window):
        """One GraphQL request for the window; at most PAGE_SIZE rows, oldest first."""
        flt = {"datetime_leq": end, "queryName_like": "%." + suffix, **window}
        body = json.dumps({"query": QUERY, "variables": {"z": os.environ["CF_ZONE_ID"], "f": flt}}).encode()
        req = urllib.request.Request(GRAPHQL, body, {"Authorization": "Bearer " + token,
                                                     "Content-Type": "application/json"})
        with GRAPHQL_OPENER.open(req, timeout=120) as resp:
            data = json.load(resp)
        if data.get("errors"):  # log the messages only, not the full error objects
            raise RuntimeError("GraphQL error: " + "; ".join(
                str(e.get("message", "?") if isinstance(e, dict) else e)[:200] for e in data["errors"]))
        return data["data"]["viewer"]["zones"][0]["dnsAnalyticsAdaptive"]
    rows, window = [], {"datetime_geq": start}
    while True:
        batch = page(window)
        if len(batch) < PAGE_SIZE:
            return rows + batch
        last = batch[-1]["datetime"]  # re-read the boundary second whole: no dropped or repeated rows
        boundary = page({"datetime_geq": last, "datetime_leq": last})
        if len(boundary) >= PAGE_SIZE:
            raise RuntimeError(f"{PAGE_SIZE}+ sampled rows at {last}; cannot page without losing rows")
        rows += [r for r in batch if r["datetime"] != last] + boundary
        window = {"datetime_gt": last}


def origin_asns(ip):
    """Origin AS numbers of the most specific announced prefix covering ip (Team Cymru), or None."""
    import dns.resolver
    try:
        addr = ipaddress.ip_address(ip)
        zone = "origin.asn.cymru.com" if addr.version == 4 else "origin6.asn.cymru.com"
        answer = dns.resolver.resolve(addr.reverse_pointer.rsplit(".", 2)[0] + "." + zone, "TXT", lifetime=10)
        recs = [[f.strip() for f in r.to_text().strip('"').split("|")] for r in answer]
        plen = [ipaddress.ip_network(f[1], strict=False).prefixlen for f in recs]
        return {int(a) for f, n in zip(recs, plen) if n == max(plen) for a in f[0].split()}
    except Exception:
        return None


def published_ranges():
    """{provider: [ip_network]} from Google's and Cloudflare's published egress lists."""
    def get(url):
        """GET a JSON document."""
        with urllib.request.urlopen(url, timeout=60) as resp:
            return json.load(resp)
    try:
        google = [p.get("ipv4Prefix") or p["ipv6Prefix"] for p in get(GOOGLE_RANGES)["prefixes"]]
    except Exception:
        import dns.resolver
        google = [s.decode().split()[0] for r in dns.resolver.resolve(GOOGLE_RANGES_TXT, "TXT", lifetime=30)
                  for s in r.strings]
    try:
        cf = get(CLOUDFLARE_RANGES)["result"]
        cloudflare = cf["ipv4_cidrs"] + cf["ipv6_cidrs"]
    except Exception:
        cloudflare = CLOUDFLARE_SNAPSHOT
    if len(google) < 100:
        raise RuntimeError(f"Google Public DNS egress list looks incomplete ({len(google)} prefixes)")
    return {name: [ipaddress.ip_network(n) for n in nets]
            for name, nets in (("google", google), ("cloudflare", cloudflare), ("ffmuc", FFMUC_RANGES))}


def exit_probabilities():
    """{fingerprint: exit_probability} for running exits from Onionoo, or {} if unavailable."""
    try:
        with urllib.request.urlopen(ONIONOO, timeout=60) as resp:
            return {r["fingerprint"]: r.get("exit_probability") or 0.0 for r in json.load(resp)["relays"]}
    except Exception as e:
        print(f"Onionoo unavailable ({e}); resolver shares unweighted", file=sys.stderr)
        return {}


def load_previous(path, current_path, current_ts, limit=LOOKBACK):
    """Earlier reports with resolver data, newest first: PREVIOUS_REPORT_JSON, then the
    dns_health_*.json files named before the current one. Only strictly older reports count."""
    if not path:
        return []
    name = os.path.basename(current_path)
    older = sorted((p for p in glob.glob(os.path.join(os.path.dirname(path), "dns_health_*.json"))
                    if os.path.basename(p) < name), reverse=True)[:2 * limit]
    found, seen_ts = [], set()
    for p in [path] + older:
        try:
            with open(p) as f:
                prev = json.load(f)
            ts = prev["metadata"]["timestamp"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if prev["metadata"].get("resolvers") and ts not in seen_ts and epoch(ts) < current_ts:
            found.append(prev)
            seen_ts.add(ts)
        if len(found) == limit:
            break
    return sorted(found, key=lambda r: epoch(r["metadata"]["timestamp"]), reverse=True)


def scan_window(report):
    """(start, end) of the scan: first/last result timestamp padded by WINDOW_PAD."""
    ts = [r["timestamp"] for r in report["results"] if r.get("timestamp")]
    return iso(min(ts) - WINDOW_PAD), iso(max(ts) + WINDOW_PAD)


def add_resolver_stats(report, rows, previous=None, ranges=None, origin=origin_asns, weights=None):
    """Add results[].resolver and metadata.resolvers to report from this scan's sampled rows plus
    decayed counts from previous (a report or a newest-first list). Raises, leaving report
    unchanged, when there is nothing to publish or the data looks broken."""
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
    ranges = published_ranges() if ranges is None else ranges
    ips = sorted({ip for c in est.values() for ip in c})
    exit_ip = {r["exit_fingerprint"]: r.get("exit_address") for r in results if r.get("exit_fingerprint") in est}
    public = {}
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        public[ip] = next((name for name, nets in ranges.items()
                           if any(addr.version == n.version and addr in n for n in nets)), None)
    need = sorted({ip for ip in ips if not public[ip]} | {e for e in exit_ip.values() if e})
    with ThreadPoolExecutor(32) as pool:
        asns = dict(zip(need, pool.map(origin, need)))
    for ip in ips:
        if not public[ip]:
            public[ip] = next((PUBLIC_ASNS[a] for a in sorted(asns[ip] or ()) if a in PUBLIC_ASNS), None)

    def category(fp, ip):
        """Category of resolver ip for the exit with fingerprint fp."""
        if ip == exit_ip.get(fp):  # the exit's own address, even inside a provider's range (e.g. NAT)
            return "local"
        if public[ip]:
            return public[ip]
        if asns[ip] is None:
            return "unknown"
        return "local" if asns.get(exit_ip.get(fp)) and asns[ip] & asns[exit_ip[fp]] else "other"
    new = {fp: Counter() for fp in est}
    for fp, c in est.items():
        for ip, n in c.items():
            new[fp][category(fp, ip)] += n
    new_est = sum(sum(c.values()) for c in new.values())
    lost = sum(c["unknown"] for c in new.values())
    if new_est and lost > MAX_UNKNOWN * new_est:
        raise RuntimeError(f"resolver AS lookups failed for {lost} of {new_est} estimated queries")
    now, carried = epoch(report["metadata"]["timestamp"]), {}
    for prev in ([previous] if isinstance(previous, dict) else previous or []):  # newest first
        hours = (now - epoch(prev["metadata"]["timestamp"])) / 3600
        if hours <= 0:
            raise RuntimeError("previous report is not older than the current one")
        decay = 0.5 ** (hours / HALF_LIFE_H)
        for p in prev["results"]:
            fp = p.get("exit_fingerprint")
            if p.get("resolver") and fp not in carried:
                carried[fp] = {k: v * decay for k, v in (p["resolver"].get("queries") or {}).items()}
    for r in results:
        q = Counter(carried.get(r.get("exit_fingerprint"), {}))
        q.update(new.get(r.get("exit_fingerprint"), {}))
        q = {k: round(v, 2) for k, v in sorted(q.items()) if v >= FLOOR}
        if q:
            primary = max(q, key=q.get) if sum(q.values()) >= LABEL else None
            r["resolver"] = {"primary": primary,
                             "public": primary in PROVIDERS if primary not in (None, "unknown") else None,
                             "queries": q}
    weights = exit_probabilities() if weights is None else weights
    ok = [r for r in results if r.get("status") == "success"]
    share, wsum, seen, labelled, using_public = Counter(), 0.0, 0, 0, 0
    for r in ok:
        used = r.get("resolver", {}).get("queries", {})
        total = sum(used.values())
        if total < SEEN:
            continue
        seen += 1
        labelled += total >= LABEL
        using_public += r["resolver"]["public"] is True
        w = weights.get(r.get("exit_fingerprint"), 0.0) if weights else 1.0
        wsum += w
        for k, v in used.items():
            share[k] += w * v / total
    pct = {p: round(100 * share[p] / wsum, 2) if wsum else 0.0 for p in CATEGORIES}
    public_pct = {p: pct[p] for p in PROVIDERS}
    public_pct["all"] = round(sum(public_pct.values()), 2)
    start, end = scan_window(report)
    report["metadata"]["resolvers"] = {
        "version": 1, "source": "cloudflare-dns-analytics-sampled", "window": {"start": start, "end": end},
        "rows": n_rows, "est_queries": n_est, "half_life_hours": HALF_LIFE_H,
        "thresholds": {"seen": SEEN, "label": LABEL}, "weighted": bool(weights),
        "exits_total": len(ok), "exits_covered": seen, "exits_labelled": labelled,
        "exits_using_public": using_public, "public_share_pct": public_pct, "share_pct": pct,
        "classification": {"google": GOOGLE_RANGES, "cloudflare": CLOUDFLARE_RANGES,
                           "quad9": "AS42 AS715 AS1288 AS19281", "opendns": "AS36692",
                           "ffmuc": " ".join(FFMUC_RANGES),
                           "local": "the exit's own address or its origin AS",
                           "unknown": "origin AS lookup failed"}}
    return report["metadata"]["resolvers"]


def main(report_path, previous_path=None):
    """Update REPORT_JSON in place (atomically) and print the summary."""
    with open(report_path) as f:
        report = json.load(f)
    start, end = scan_window(report)
    suffix = os.environ.get("DNS_WILDCARD_DOMAIN", "tor.exit.validator.1aeo.com").lower().strip(".")
    previous = load_previous(previous_path, report_path, epoch(report["metadata"]["timestamp"]))
    summary = add_resolver_stats(report, graphql_rows(start, end, suffix), previous)
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
