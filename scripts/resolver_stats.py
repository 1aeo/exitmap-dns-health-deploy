#!/usr/bin/env python3
"""
Estimate which DNS resolver each exit uses, from Cloudflare's sampled DNS analytics.

Usage: resolver_stats.py REPORT_JSON [PREVIOUS_REPORT_JSON]

Fetches the validator zone's queries for the scan window from the GraphQL
dnsAnalyticsAdaptive dataset (env CF_ANALYTICS_TOKEN, CF_ZONE_ID), maps each query
to its exit via the fp8 label, classifies the querying resolver and adds
results[].resolver plus metadata.resolvers (version 2) to REPORT_JSON in place.
Per-exit counts are sample-weighted estimates carried forward from earlier reports
with a 3.5-day half-life. On any error the report is left unchanged.

Categories, first match wins: the exit's own address or the same IPv4 /24 (IPv6 /64)
is local_24; the same IPv4 /22 (IPv6 /48) but not that tighter prefix is local_22;
the same origin AS outside those prefixes is local_as; a resolver run by the same
operator outside the exit's prefix and AS is local_operator. Public providers
(google, cloudflare, quad9, opendns, ffmuc) are unchanged and win over every local
tier except the exit's own address. Anything else is other, or unknown when the
origin-AS lookup failed.
"""

import glob, gzip, ipaddress, json, os, re, sys, time, urllib.parse, urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone

# Public resolver services. A query counts for one only when its source IP is covered by what
# the operator itself publishes about the addresses its resolver queries authoritative servers
# from (sources checked 2026-10-12). Otherwise the resolver is one of the local tiers below,
# "other", or "unknown" (no AS data). Every category counts toward the shares: they all
# describe resolvers the exits really used.
#
# Local tiers use the exit's own addresses and, for local_operator, its operator group.
# Prefix tests never cross address families (an IPv6 resolver is compared only with the
# exit's IPv6 addresses). They do not need an AS lookup. Historical reports use that
# report's exit_address plus current Onionoo addresses for the rest; Onionoo is live, so
# a relay that has since moved is only an approximation.
#
#   local_24        same IPv4 /24 or IPv6 /64 as the exit, including the exit's own address
#   local_22        same IPv4 /22 or IPv6 /48, but not the same /24 or /64
#   local_as        same origin AS as one of the exit's addresses, outside those prefixes
#   local_operator  same operator, but outside the exit's /22 (/48) and origin AS.
#                   The operator group is Onionoo effective_family, plus relays that share
#                   the exit's validated AROI domain (https://aroivalidator.1aeo.com/latest.json,
#                   results[].valid == true). When that domain is missing, relays with the
#                   same normalized ContactInfo string are the fallback; ContactInfo is
#                   unverified. A resolver matches the group by address, by the IPv4 /24 or
#                   IPv6 /48 of a group address, by a forward-confirmed reverse DNS name
#                   under an operator domain (the AROI domain, or a ContactInfo url:/email:
#                   domain), or by a forward-confirmed name that carries the operator's name
#                   from a validated AROI domain as a whole label (artikel10.org -> a resolver
#                   named artikel10.in-berlin.de at its hoster). That name must be at least
#                   NAME_MIN characters and not a generic word (GENERIC_NAMES). AS equality
#                   alone is not an operator match: a hoster such as OVH or Hetzner also hosts
#                   other operators' resolvers.
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
LOCAL_TIERS = ("local_24", "local_22", "local_as", "local_operator")
CATEGORIES = PROVIDERS + LOCAL_TIERS + ("other", "unknown")
# `as` is part of the directory snapshot the operator group is built from. Classification does
# not use it: Onionoo's AS can be the network the relay is announced in, while local_as is the
# Team Cymru origin AS of each of the exit's addresses.
ONIONOO_URL = ("https://onionoo.torproject.org/details?type=relay&running=true"
               "&fields=fingerprint,or_addresses,exit_addresses,effective_family,contact,as,exit_probability")
AROI_URL = "https://aroivalidator.1aeo.com/latest.json"
GRAPHQL = "https://api.cloudflare.com/client/v4/graphql"
QUERY = """query($z:String!,$f:ZoneDnsAnalyticsAdaptiveFilter_InputObject!){viewer{zones(filter:{zoneTag:$z}){
dnsAnalyticsAdaptive(filter:$f,limit:10000,orderBy:[datetime_ASC]){datetime queryName sourceIP sampleInterval}}}}"""
PAGE_SIZE = 10000
WINDOW_PAD = 300     # seconds around the scan's first/last result
HALF_LIFE_H = 84     # carry-forward half-life (3.5 days)
SEEN, LABEL = 5, 25  # decayed estimated queries to count an exit as seen / to label it
FLOOR = 1            # drop a category once its decayed estimate falls below one query
LOOKBACK = 10        # earlier reports searched for an exit's carried counts
MAX_UNKNOWN = 0.5    # abort if origin-AS lookups fail for more than this share (outage guard)
FCRDNS_MAX = 2000    # reverse-DNS checks per run, resolver IPs with the most estimated queries first
FCRDNS_BUDGET = 180  # seconds for all reverse-DNS checks; checks still running count as no match
FCRDNS_NAMES = 4     # PTR names forward-checked per IP, only names under a candidate operator domain
_FETCH_ATTEMPTS = 3
NAME_MIN = 5         # shortest operator name (from a validated AROI domain) matched inside a hostname
GENERIC_NAMES = frozenset({  # words too common in hostnames to identify an operator
    "relay", "relays", "exits", "exitnode", "nodes", "router", "resolver", "resolv", "resolve",
    "privacy", "server", "servers", "proxy", "cloud", "hosting", "network", "networks", "internet",
    "online", "digital", "global", "secure", "security", "anonymous", "onion", "onions", "freedom",
    "email", "admin", "local", "static", "dynamic", "client", "customer", "dedicated", "example",
    "torproject", "github", "gitlab", "google", "cloudflare", "amazon", "microsoft", "public",
    "service", "services", "infra", "gateway", "default"})
_SECOND_LEVEL = frozenset({"co", "com", "net", "org", "ac", "gov", "edu", "ne", "or", "go"})
_CONTACT_FIELD = re.compile(r"(?:^|\s)(url|email):(\S+)", re.IGNORECASE)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects, so the Authorization header never follows a 3xx to another URL."""

    def redirect_request(self, *args, **kwargs):
        """Returning None makes urllib raise HTTPError for the 3xx instead of following it."""
        return None


GRAPHQL_OPENER = urllib.request.build_opener(NoRedirect)


def epoch(iso_ts):
    """ISO-8601 UTC timestamp ("...Z" or "+00:00") -> epoch seconds."""
    return datetime.fromisoformat(iso_ts.replace("Z", "+00:00")).timestamp()


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


def fetch_json(url, timeout):
    """GET url and parse a JSON body. No Authorization header is sent.

    Redirects are refused, same as the GraphQL client. These calls carry no
    credentials; refusing a 3xx keeps a directory host from sending the cron
    job to some other URL.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "exitdnshealth-resolver-stats"})
    try:
        with GRAPHQL_OPENER.open(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            host = urllib.parse.urlparse(url).hostname or "directory host"
            raise RuntimeError(f"refusing redirect from {host}") from None
        raise


def fetch_onionoo():
    """Running-relay details from Onionoo. Raises after retries if the directory is unusable.

    Address, family and exit-probability data have to come from one snapshot so the
    categories and the shares describe the same network. A missed scan is covered by
    the lookback, so failing the resolver step is safer than publishing a partial view.
    """
    last = "no attempt"
    for attempt in range(_FETCH_ATTEMPTS):
        try:
            data = fetch_json(ONIONOO_URL, timeout=90)
            relays = data.get("relays") if isinstance(data, dict) else None
            if not isinstance(relays, list) or not relays:
                raise RuntimeError("Onionoo returned no relays")
            return relays
        except Exception as e:
            last = e
            if attempt + 1 < _FETCH_ATTEMPTS:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"Onionoo unavailable: {last}")


def fetch_aroi():
    """Validated AROI rows, or None when the file cannot be fetched.

    None means continue without the AROI part of the operator group. An empty list
    means the file was fetched and no relay is currently validated.
    """
    try:
        data = fetch_json(AROI_URL, timeout=60)
    except Exception as e:
        print(f"AROI validator unavailable ({e}); operator groups omit AROI domains", file=sys.stderr)
        return None
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        print("AROI validator unavailable (no results); operator groups omit AROI domains", file=sys.stderr)
        return None
    return results


def parse_address(value):
    """IP from a bare address, '1.2.3.4:port', or '[2001:db8::1]:port'. None if it is not an IP."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    if value.startswith("["):
        end = value.find("]")
        host = value[1:end] if end > 1 else ""
    elif value.count(":") == 1:
        host = value.rsplit(":", 1)[0]
    else:
        host = value
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def norm_contact(contact):
    """ContactInfo compared for the operator fallback: lowercased, whitespace collapsed.

    The string is not authenticated. Operators who publish the same contact text are
    grouped only when a validated AROI domain is not available for the exit.
    A missing or non-string value is ignored so a bad directory record cannot abort
    the resolver step.
    """
    if not isinstance(contact, str):
        return ""
    return " ".join(contact.lower().split())


def norm_domain(value):
    """Registrable-looking hostname: lowercased, no trailing dot, a leading www. removed."""
    value = (value or "").strip().lower().strip(".")
    if value.startswith("www."):
        value = value[4:]
    if not value or "." not in value or any(c in value for c in " /\\@"):
        return ""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    return ""


def contact_domains(contact):
    """Domains named by CIISS url: and email: in contact. '[]' stands for '@'.

    Only those two keys count. Other contact text is not a domain signal.
    A missing or non-string contact yields no domains.
    """
    if not isinstance(contact, str):
        return set()
    domains = set()
    for key, raw in _CONTACT_FIELD.findall(contact):
        raw = raw.strip().strip("<>\"'")
        if key.lower() == "email":
            raw = raw.replace("[]", "@")
            host = raw.rsplit("@", 1)[1] if "@" in raw else ""
        else:
            url = raw if "://" in raw else "http://" + raw
            try:
                host = urllib.parse.urlparse(url).hostname or ""
            except ValueError:  # e.g. unbalanced brackets in operator-supplied text
                continue
        domain = norm_domain(host)
        if domain:
            domains.add(domain)
    return domains


def name_in_domain(name, domain):
    """True when a DNS name is the domain or a subdomain of it."""
    name = (name or "").lower().rstrip(".")
    domain = (domain or "").lower().strip(".")
    return bool(domain) and (name == domain or name.endswith("." + domain))


def operator_name(domain):
    """The operator's name inside a validated AROI domain, for matching hostname labels.

    The label left of the registrable suffix: artikel10.org -> artikel10, relays.example.org
    -> example, foo.co.uk -> foo. Empty when the label is shorter than NAME_MIN, all digits,
    or a generic word, so only distinctive names can match.
    """
    labels = [label for label in norm_domain(domain).split(".") if label]
    if len(labels) < 2:
        return ""
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        name = labels[-3]
    else:
        name = labels[-2]
    if len(name) < NAME_MIN or name.isdigit() or name in GENERIC_NAMES:
        return ""
    return name


def has_label(name, labels):
    """True when one of a DNS name's labels is in labels (whole-label match)."""
    return bool(labels) and any(part in labels for part in (name or "").lower().rstrip(".").split("."))


def fcrdns_names(ip, domains=None, names=None):
    """Forward-confirmed reverse DNS names for ip (PTR whose A/AAAA includes ip).

    Names that do not resolve back to ip are dropped. Lookup failure is an empty set,
    not an error: the resolver can still be other or unknown. With domains or names, only
    PTR names under one of the domains or carrying one of the names as a whole label are
    forward-checked; at most FCRDNS_NAMES names either way, so a reverse zone with many
    slow names cannot stall the run.
    """
    import dns.resolver
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return set()
    try:
        ptrs = dns.resolver.resolve(addr.reverse_pointer, "PTR", lifetime=5)
    except Exception:
        return set()
    rdtype = "A" if addr.version == 4 else "AAAA"
    candidates = sorted({ptr.to_text().rstrip(".").lower() for ptr in ptrs})
    if domains is not None or names is not None:
        candidates = [name for name in candidates
                      if any(name_in_domain(name, d) for d in domains or ()) or has_label(name, names)]
    names = set()
    for name in candidates[:FCRDNS_NAMES]:
        try:
            answers = dns.resolver.resolve(name, rdtype, lifetime=5)
        except Exception:
            continue
        for ans in answers:
            try:
                if ipaddress.ip_address(ans.to_text()) == addr:
                    names.add(name)
                    break
            except ValueError:
                continue
    return names


def confirm_names(ips, domains_of, names_of=None):
    """fcrdns_names for each ip within FCRDNS_BUDGET seconds. Checks that have not finished
    by then count as no names; the run reports how many were skipped."""
    if not ips:
        return {}
    names_of = names_of or {}
    pool = ThreadPoolExecutor(32)
    futures = {pool.submit(fcrdns_names, ip, domains_of.get(ip, set()), names_of.get(ip, set())): ip
               for ip in ips}
    done, pending = wait(futures, timeout=FCRDNS_BUDGET)
    pool.shutdown(wait=False, cancel_futures=True)
    if pending:
        print(f"Reverse DNS budget reached: {len(pending)} of {len(ips)} checks skipped", file=sys.stderr)
    return {futures[future]: future.result() for future in done}


def resolvers_version(report):
    """metadata.resolvers.version of a report, or None."""
    resolvers = (report.get("metadata") or {}).get("resolvers") if isinstance(report, dict) else None
    return resolvers.get("version") if isinstance(resolvers, dict) else None


def primary_of(queries):
    """Primary category, or None below LABEL estimated queries.

    The four local tiers compete as one group, as version 1's single "local" did, so an
    exit whose own resolvers span two tiers is not labelled by a smaller public share.
    When that group wins, the primary is its largest tier.
    """
    if sum(queries.values()) < LABEL:
        return None
    local = {k: v for k, v in queries.items() if k in LOCAL_TIERS}
    groups = {k: v for k, v in queries.items() if k not in LOCAL_TIERS}
    if local:
        groups["local"] = sum(local.values())
    top = max(groups, key=groups.get)
    return max(local, key=local.get) if top == "local" else top


def fingerprint_of(value):
    """Onionoo/AROI fingerprint as uppercase hex without a leading '$', or ''."""
    return str(value or "").strip().lstrip("$").upper()


def weights_from_relays(relays):
    """{fingerprint: exit_probability} for relays Onionoo published a positive probability for."""
    weights = {}
    for relay in relays:
        fp = fingerprint_of(relay.get("fingerprint"))
        prob = relay.get("exit_probability")
        if not fp or isinstance(prob, bool) or not isinstance(prob, (int, float)) or prob <= 0:
            continue
        weights[fp] = float(prob)
    return weights


def load_previous(path, current_path, current_ts, limit=LOOKBACK):
    """Earlier version-2 reports, newest first, from the dns_health_*.json files named before
    the current one and PREVIOUS_REPORT_JSON (latest.json) as a fallback. Only strictly older
    reports count. A dns_health file wins a timestamp tie, so a stale latest.json cannot hide
    a rewritten report; version-1 reports are skipped because their "local" has no tiers and
    carrying the rest of a v1 block would bias the shares toward public and other."""
    if not path:
        return []
    name = os.path.basename(current_path)
    older = sorted((p for p in glob.glob(os.path.join(os.path.dirname(path), "dns_health_*.json"))
                    if os.path.basename(p) < name), reverse=True)[:2 * limit]
    found, seen_ts = [], set()
    for p in older + [path]:
        try:
            with open(p) as f:
                prev = json.load(f)
            ts = prev["metadata"]["timestamp"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if resolvers_version(prev) == 2 and ts not in seen_ts and epoch(ts) < current_ts:
            found.append(prev)
            seen_ts.add(ts)
        if len(found) == limit:
            break
    return sorted(found, key=lambda r: epoch(r["metadata"]["timestamp"]), reverse=True)


def scan_window(report):
    """(start, end) of the scan: first/last result timestamp padded by WINDOW_PAD."""
    ts = [r["timestamp"] for r in report["results"] if r.get("timestamp")]
    return iso(min(ts) - WINDOW_PAD), iso(max(ts) + WINDOW_PAD)


def archive_rows(report_path, rows):
    """Write this scan's sampled rows as gzipped JSON lines under data/resolver_rows/.

    The directory is outside public/ and is gitignored. DigitalOcean Spaces objects are
    publicly readable, so these files must never be uploaded. A failure is logged and
    does not fail the resolver step.
    """
    try:
        deploy = os.environ.get("DEPLOY_DIR") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dest_dir = os.path.join(deploy, "data", "resolver_rows")
        os.makedirs(dest_dir, mode=0o700, exist_ok=True)
        os.chmod(dest_dir, 0o700)
        base = os.path.basename(report_path)
        if base.endswith(".json"):
            base = base[:-5]
        path = os.path.join(dest_dir, base + ".jsonl.gz")
        with gzip.open(path, "wt", encoding="utf-8") as out:
            for row in rows:
                out.write(json.dumps({
                    "datetime": row.get("datetime"),
                    "queryName": row.get("queryName"),
                    "sourceIP": row.get("sourceIP"),
                    "sampleInterval": row.get("sampleInterval"),
                }, separators=(",", ":")) + "\n")
        os.chmod(path, 0o600)
    except Exception as e:
        print(f"Resolver row archive skipped: {e!r}", file=sys.stderr)


def _containing(addr, prefixlen):
    """The prefixlen network that contains addr."""
    return ipaddress.ip_network(f"{addr}/{prefixlen}", strict=False)


def _relay_addresses(relay):
    """IPv4 and IPv6 addresses from one relay's or_addresses and exit_addresses."""
    found = []
    for field in ("or_addresses", "exit_addresses"):
        for raw in relay.get(field) or []:
            addr = parse_address(raw)
            if addr is not None:
                found.append(addr)
    return found


def _index_relays(relays):
    """fingerprint -> relay, plus contact -> fingerprints for the ContactInfo fallback."""
    by_fp, by_contact = {}, defaultdict(set)
    for relay in relays or []:
        if not isinstance(relay, dict):
            continue
        fp = fingerprint_of(relay.get("fingerprint"))
        if not fp:
            continue
        by_fp[fp] = relay
        contact = norm_contact(relay.get("contact"))
        if contact:
            by_contact[contact].add(fp)
    return by_fp, by_contact


def _index_aroi(results, available):
    """fingerprint -> validated domain, and domain -> fingerprints. Empty when unavailable."""
    domain_of, by_domain = {}, defaultdict(set)
    if not available:
        return domain_of, by_domain
    for row in results or []:
        if not isinstance(row, dict) or row.get("valid") is not True:
            continue
        fp = fingerprint_of(row.get("fingerprint"))
        raw_domain = row.get("domain")
        if not isinstance(raw_domain, str):
            continue
        domain = norm_domain(raw_domain)
        if fp and domain:
            domain_of[fp] = domain
            by_domain[domain].add(fp)
    return domain_of, by_domain


def _operator_group(fp, by_fp, by_contact, aroi_domain, aroi_by_domain, aroi_available):
    """Fingerprints in fp's operator group (family, AROI domain, or contact fallback)."""
    fp = fingerprint_of(fp)
    group = set()
    relay = by_fp.get(fp)
    if relay:
        group.add(fp)
        for member in relay.get("effective_family") or []:
            member_fp = fingerprint_of(member)
            if member_fp in by_fp:
                group.add(member_fp)
    domain = aroi_domain.get(fp) if aroi_available else None
    if domain:
        group |= aroi_by_domain.get(domain, set())
    elif relay:
        contact = norm_contact(relay.get("contact"))
        if contact:
            group |= by_contact.get(contact, set())
    return group


def _group_footprint(members, by_fp, aroi_domain, use_contact):
    """Addresses, IPv4 /24s, IPv6 /48s, domains and operator names of an operator group.

    Validated AROI domains always count, and only they supply operator names. ContactInfo
    url:/email: domains are unverified, so they count only when the exit itself has no
    validated AROI domain (the contact fallback).
    """
    addrs, nets4, nets6, domains, names = set(), set(), set(), set(), set()
    for member in members:
        domain = aroi_domain.get(member)
        if domain:
            domains.add(domain)
            if operator_name(domain):
                names.add(operator_name(domain))
        relay = by_fp.get(member)
        if not relay:
            continue
        if use_contact:
            domains |= contact_domains(relay.get("contact"))
        for addr in _relay_addresses(relay):
            addrs.add(addr)
            if addr.version == 4:
                nets4.add(_containing(addr, 24))
            else:
                nets6.add(_containing(addr, 48))
    return addrs, nets4, nets6, domains, names


def add_resolver_stats(report, rows, previous=None, ranges=None, origin=origin_asns, weights=None,
                       relays=None, aroi=None, aroi_available=None, fcrdns=None):
    """Add results[].resolver and metadata.resolvers (version 2) to report.

    rows are this scan's sampled analytics records. previous is one report or a
    newest-first list; carried query keys that are not version-2 categories (for
    example a legacy "local") are dropped. ranges, origin, relays, aroi and fcrdns
    override the live lookups so tests and a backfill can inject data. relays=None
    fetches Onionoo and raises if it is unreachable. aroi=None fetches AROI; a failed
    fetch continues with aroi_available false. fcrdns(ip) returns forward-confirmed
    names. Raises, leaving report unchanged, when there is nothing to publish or the
    data looks broken.
    """
    results = report["results"]
    suffix = "." + os.environ.get("DNS_WILDCARD_DOMAIN", "tor.exit.validator.1aeo.com").lower().strip(".")
    by_fp8 = {}
    for result in results:
        fp8 = (result.get("exit_fingerprint") or "")[:8].lower()
        by_fp8[fp8] = None if fp8 in by_fp8 else result  # drop ambiguous prefixes
    est, n_rows, n_est = defaultdict(Counter), 0, 0
    for row in rows:
        name = row["queryName"].lower().rstrip(".")
        if not name.endswith(suffix):
            continue
        n_rows += 1
        n_est += row["sampleInterval"]
        try:
            source = str(ipaddress.ip_address(row["sourceIP"]))
        except (ValueError, TypeError):
            raise RuntimeError("sampled row has an invalid sourceIP")
        result = by_fp8.get(name[:-len(suffix)].rsplit(".", 1)[-1])
        if result:
            est[result["exit_fingerprint"]][source] += row["sampleInterval"]
    if not n_rows:
        raise RuntimeError("no validator queries in the scan window")

    if relays is None:
        relays = fetch_onionoo()
    if aroi_available is None:
        if aroi is None:
            aroi = fetch_aroi()
            aroi_available = aroi is not None
        else:
            aroi_available = True
    aroi = aroi or []
    relays_by_fp, relays_by_contact = _index_relays(relays)
    aroi_domain, aroi_by_domain = _index_aroi(aroi, aroi_available)
    if weights is None:
        weights = weights_from_relays(relays)

    ranges = published_ranges() if ranges is None else ranges
    provider_of = {}
    for ip in {ip for counts in est.values() for ip in counts}:
        addr = ipaddress.ip_address(ip)
        provider_of[ip] = next((name for name, nets in ranges.items()
                                if any(addr.version == net.version and addr in net for net in nets)), None)

    exit_addrs = {}
    for result in results:
        fp = result.get("exit_fingerprint")
        if fp not in est:
            continue
        addrs = set()
        own = parse_address(result.get("exit_address") or "")
        if own is not None:
            addrs.add(own)
        relay = relays_by_fp.get(fingerprint_of(fp))
        if relay:
            addrs.update(_relay_addresses(relay))
        exit_addrs[fp] = addrs

    need = {ip for ip, provider in provider_of.items() if not provider}
    need |= {str(addr) for addrs in exit_addrs.values() for addr in addrs}
    if need:
        ordered = sorted(need)
        with ThreadPoolExecutor(32) as pool:
            looked = dict(zip(ordered, pool.map(origin, ordered)))
    else:
        looked = {}
    # Outage guard. Published ranges, the exit's own address and the prefix tiers need no AS
    # data, so during a Team Cymru or resolver outage "unknown" alone stays small while quad9,
    # opendns, local_as and other silently vanish. Count the failed lookups instead.
    failed = {ip for ip, asns in looked.items() if asns is None}
    needed = sum(n for counts in est.values() for ip, n in counts.items() if ip in looked)
    lost = sum(n for counts in est.values() for ip, n in counts.items() if ip in failed)
    if (needed and lost > MAX_UNKNOWN * needed) or (looked and len(failed) > MAX_UNKNOWN * len(looked)):
        raise RuntimeError(f"origin AS lookups failed for {len(failed)} of {len(looked)} addresses "
                           f"({lost} of {needed} estimated queries)")
    for ip, provider in list(provider_of.items()):
        if not provider:
            provider_of[ip] = next((PUBLIC_ASNS[asn] for asn in sorted(looked.get(ip) or ())
                                    if asn in PUBLIC_ASNS), None)

    footprints, by_members = {}, {}

    def footprint(fp):
        """Cached operator-group addresses, prefixes and domains for one exit."""
        if fp not in footprints:
            members = _operator_group(fp, relays_by_fp, relays_by_contact, aroi_domain,
                                      aroi_by_domain, aroi_available)
            use_contact = not (aroi_available and aroi_domain.get(fingerprint_of(fp)))
            key = (tuple(sorted(members)), use_contact)
            if key not in by_members:
                by_members[key] = _group_footprint(members, relays_by_fp, aroi_domain, use_contact)
            footprints[fp] = by_members[key]
        return footprints[fp]

    contexts = {}
    for fp, addrs in exit_addrs.items():
        v4 = {addr for addr in addrs if addr.version == 4}
        v6 = {addr for addr in addrs if addr.version == 6}
        asns = set()
        for addr in addrs:
            asns |= looked.get(str(addr)) or set()
        op_addrs, op24, op48, domains, names = footprint(fp)
        contexts[fp] = {
            "addrs": addrs,
            "v4_24": {_containing(addr, 24) for addr in v4},
            "v4_22": {_containing(addr, 22) for addr in v4},
            "v6_64": {_containing(addr, 64) for addr in v6},
            "v6_48": {_containing(addr, 48) for addr in v6},
            "asns": asns, "op_addrs": op_addrs, "op24": op24, "op48": op48, "domains": domains,
            "names": names,
        }

    def network_category(fp, ip):
        """Category from steps 1-5, or None when the resolver is still unmatched."""
        addr = ipaddress.ip_address(ip)
        ctx = contexts[fp]
        if addr in ctx["addrs"]:  # own address, even inside a provider range (NAT)
            return "local_24"
        if provider_of.get(ip):
            return provider_of[ip]
        if addr.version == 4:
            if _containing(addr, 24) in ctx["v4_24"]:
                return "local_24"
            if _containing(addr, 22) in ctx["v4_22"]:
                return "local_22"
        else:
            if _containing(addr, 64) in ctx["v6_64"]:
                return "local_24"
            if _containing(addr, 48) in ctx["v6_48"]:
                return "local_22"
        got = looked.get(ip)
        if got and ctx["asns"] and got & ctx["asns"]:
            return "local_as"
        return None

    def operator_reason(fp, ip, confirmed):
        """Which operator signal matches, or None. Address, prefix, FCrDNS domain, then name."""
        addr = ipaddress.ip_address(ip)
        ctx = contexts[fp]
        if addr in ctx["op_addrs"]:
            return "address"
        if addr.version == 4 and _containing(addr, 24) in ctx["op24"]:
            return "prefix"
        if addr.version == 6 and _containing(addr, 48) in ctx["op48"]:
            return "prefix"
        if any(name_in_domain(name, domain) for name in confirmed for domain in ctx["domains"]):
            return "fcrdns"
        if any(has_label(name, ctx["names"]) for name in confirmed):
            return "name"
        return None

    # Reverse DNS only for still-unmatched resolver IPs whose exits have an operator domain the
    # name could sit under; heaviest first and capped, because anyone can add sampled queries
    # (and so resolver IPs with slow reverse zones) during a scan window.
    domains_of, names_of, weight_of = defaultdict(set), defaultdict(set), Counter()
    for fp, counts in est.items():
        ctx = contexts[fp]
        for ip, n in counts.items():
            if network_category(fp, ip) is None and (ctx["domains"] or ctx["names"]):
                domains_of[ip] |= ctx["domains"]
                names_of[ip] |= ctx["names"]
                weight_of[ip] += n
    todo = sorted(weight_of, key=lambda ip: (-weight_of[ip], ip))
    if len(todo) > FCRDNS_MAX:
        print(f"Reverse DNS capped: {len(todo) - FCRDNS_MAX} of {len(todo)} resolver IPs not checked",
              file=sys.stderr)
        todo = todo[:FCRDNS_MAX]
    if fcrdns is None:
        confirmed = confirm_names(todo, domains_of, names_of)
    else:
        confirmed = {ip: set(fcrdns(ip) or ()) for ip in todo}

    def classify(fp, ip):
        """(category, operator signal or None) for resolver ip used by exit fp."""
        hit = network_category(fp, ip)
        if hit:
            return hit, None
        reason = operator_reason(fp, ip, confirmed.get(ip) or set())
        if reason:
            return "local_operator", reason
        if looked.get(ip) is None:
            return "unknown", None
        return "other", None

    new, signals = {fp: Counter() for fp in est}, Counter()
    for fp, counts in est.items():
        for ip, n in counts.items():
            category, reason = classify(fp, ip)
            new[fp][category] += n
            if reason:
                signals[reason] += n

    now, carried = epoch(report["metadata"]["timestamp"]), {}
    previous = [previous] if isinstance(previous, dict) else list(previous or [])
    previous = [prev for prev in previous if resolvers_version(prev) == 2]  # v1 "local" has no tiers
    previous.sort(key=lambda prev: epoch(prev["metadata"]["timestamp"]), reverse=True)
    for prev in previous:  # newest first: each exit is carried from the newest report that has it
        hours = (now - epoch(prev["metadata"]["timestamp"])) / 3600
        if hours <= 0:
            raise RuntimeError("previous report is not older than the current one")
        decay = 0.5 ** (hours / HALF_LIFE_H)
        for prev_result in prev["results"]:
            fp = prev_result.get("exit_fingerprint")
            if prev_result.get("resolver") and fp not in carried:
                queries = prev_result["resolver"].get("queries") or {}
                carried[fp] = {k: v * decay for k, v in queries.items() if k in CATEGORIES}

    updates = []
    for result in results:
        merged = Counter(carried.get(result.get("exit_fingerprint"), {}))
        merged.update(new.get(result.get("exit_fingerprint"), {}))
        queries = {k: round(v, 2) for k, v in sorted(merged.items()) if v >= FLOOR}
        if not queries:
            # Rows and earlier reports are the only source: an existing block (e.g. from an
            # in-place re-run over an already-processed report) must not survive unchanged.
            updates.append((result, None))
            continue
        primary = primary_of(queries)
        updates.append((result, {
            "primary": primary,
            "public": primary in PROVIDERS if primary not in (None, "unknown") else None,
            "queries": queries,
        }))
    for result, resolver in updates:
        if resolver:
            result["resolver"] = resolver
        else:
            result.pop("resolver", None)

    ok = [result for result in results if result.get("status") == "success"]
    share, wsum, seen, labelled, using_public = Counter(), 0.0, 0, 0, 0
    for result in ok:
        used = result.get("resolver", {}).get("queries", {})
        total = sum(used.values())
        if total < SEEN:
            continue
        seen += 1
        labelled += total >= LABEL
        using_public += result["resolver"]["public"] is True
        fp = result.get("exit_fingerprint")
        weight = (weights.get(fp, weights.get(fingerprint_of(fp), 0.0)) if weights else 1.0)
        wsum += weight
        for key, value in used.items():
            share[key] += weight * value / total
    pct = {category: round(100 * share[category] / wsum, 2) if wsum else 0.0 for category in CATEGORIES}
    public_pct = {provider: pct[provider] for provider in PROVIDERS}
    public_pct["all"] = round(sum(public_pct.values()), 2)
    start, end = scan_window(report)
    report["metadata"]["resolvers"] = {
        "version": 2, "source": "cloudflare-dns-analytics-sampled", "window": {"start": start, "end": end},
        "rows": n_rows, "est_queries": n_est, "half_life_hours": HALF_LIFE_H,
        "thresholds": {"seen": SEEN, "label": LABEL}, "weighted": bool(weights),
        "exits_total": len(ok), "exits_covered": seen, "exits_labelled": labelled,
        "exits_using_public": using_public, "public_share_pct": public_pct, "share_pct": pct,
        "operator_sources": {"onionoo": True, "aroi": bool(aroi_available)},
        "operator_signals": {"address": signals["address"], "prefix": signals["prefix"],
                             "fcrdns": signals["fcrdns"], "name": signals["name"]},
        "classification": {
            "google": GOOGLE_RANGES, "cloudflare": CLOUDFLARE_RANGES,
            "quad9": "AS42 AS715 AS1288 AS19281", "opendns": "AS36692",
            "ffmuc": " ".join(FFMUC_RANGES),
            "local_24": "same IPv4 /24 or IPv6 /64 as the exit, including the exit's own address",
            "local_22": "same IPv4 /22 or IPv6 /48 as the exit, but not the same /24 or /64",
            "local_as": "same origin AS as the exit, outside its IPv4 /22 or IPv6 /48",
            "local_operator": ("same operator (Onionoo effective_family, validated AROI domain, "
                               "or identical ContactInfo) outside the exit's prefix and AS; "
                               "matched by address, IPv4 /24 or IPv6 /48, forward-confirmed reverse DNS "
                               "under an operator domain, or a forward-confirmed name carrying the "
                               "operator's name from its validated AROI domain as a whole label"),
            "unknown": "origin AS lookup failed"},
    }
    return report["metadata"]["resolvers"]


def main(report_path, previous_path=None):
    """Update REPORT_JSON in place (atomically) and print the summary."""
    with open(report_path) as f:
        report = json.load(f)
    start, end = scan_window(report)
    suffix = os.environ.get("DNS_WILDCARD_DOMAIN", "tor.exit.validator.1aeo.com").lower().strip(".")
    rows = graphql_rows(start, end, suffix)
    # Keep the sampled rows even when classification later aborts (for example Onionoo is down).
    archive_rows(report_path, rows)
    previous = load_previous(previous_path, report_path, epoch(report["metadata"]["timestamp"]))
    summary = add_resolver_stats(report, rows, previous)
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
