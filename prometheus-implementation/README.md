# Prometheus Metrics Implementation

Implementation of the AEO1 Prometheus metrics schema v1 for Tor relay monitoring.

## Status: Implementation complete, tested, verified

### What this contains

**For `1aeo/allium` repo:**
- `allium/prometheus_metrics.py` → copy to `allium/lib/prometheus_metrics.py`
- `allium/test_prometheus_metrics.py` → copy to `tests/unit/test_prometheus_metrics.py`
- `allium/0001-feat-add-Prometheus-metrics-generation-schema-v1.patch` → full git patch (apply with `git am`)

The patch also includes small changes to:
- `allium/lib/site_generator.py` — adds prometheus generation hook after search index
- `allium/allium.py` — updates progress step count (+2 steps)

**For `1aeo/allium-deploy` repo:**
- `allium-deploy/_shared.js` → replace `functions/_shared.js`
- `allium-deploy/0001-allium-deploy-prometheus-support.patch` → git diff patch

Changes:
- `functions/_shared.js` — adds `text/plain; version=0.0.4` MIME type for `/metrics` path
- `scripts/allium-deploy-update.sh` — adds `/metrics` to CDN purge with warning on failure

## Applying the changes

### Allium
```bash
cd ~/allium
git am prometheus-implementation/allium/0001-feat-add-Prometheus-metrics-generation-schema-v1.patch
```

### Allium-deploy
```bash
cd ~/allium-deploy
git apply prometheus-implementation/allium-deploy/0001-allium-deploy-prometheus-support.patch
```

## Verification results

- **42 unit tests**: All passing
- **Baseline regression check**: Only change is the new `metrics` file (22,043 → 22,044 files)
- **Metrics file**: 20,508 lines, 2.9 MB (3,089 exit relays, 4,184 AROI relays)
- **All existing HTML files**: Unchanged (only timestamp diffs from data freshness)
- **familyid labels**: Populated from CollecTor Ed25519 keys (~2,754 relays with family keys)

## Schema v1 metrics

- `aeo1_build_info` — schema version
- `aeo1_generation_timestamp_seconds` — file generation time
- `aeo1_source_up{source="exitdnshealth|aroi"}` — source availability
- `aeo1_source_last_success_timestamp_seconds{source=...}` — last ingest time
- `aeo1_exit_dns_failed{fingerprint,familyid,status}` — per-relay DNS failure
- `aeo1_exit_dns_latency_ms{fingerprint,familyid}` — per-relay latency
- `aeo1_exit_dns_consecutive_failures{fingerprint,familyid}` — failure streak
- `aeo1_exit_relay_info{fingerprint,familyid,nick,verifiedaroi}` — relay metadata
- `aeo1_aroi_valid{fingerprint,familyid}` — per-relay AROI validation
- `aeo1_aroi_relay_info{fingerprint,familyid,nick,domain,proof_type}` — AROI metadata
- Plus aggregate metrics for both sections
