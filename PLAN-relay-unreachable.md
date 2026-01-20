# Implementation Plan: Add `relay_unreachable` Status

**Goal**: Include relays where Tor circuits failed to build in our results, so relay operators can find their relay and understand why it wasn't tested.

**Status**: ✅ Complete (2026-01-18)

---

## Summary

Currently, ~16% of exit relays (507 out of 3123) have circuit failures and are silently dropped from results. Relay operators searching for their relay won't find it and won't know why.

**Solution**: Add `relay_unreachable` as a new status category, tracking which relays had circuit failures and why.

---

## Agreed Design Decisions

| Decision | Choice |
|----------|--------|
| Status name | `relay_unreachable` |
| Array structure | **Unified** - all relays in single `results` array |
| Success rates | Two rates: `dns_success_rate_percent` + `reachability_success_rate_percent` |
| Circuit reason | Store specific Tor reason (TIMEOUT, CONNECTFAILED, etc.) |
| Detail level | Simple at high level, detailed in JSON |

---

## Final JSON Structure

```json
{
  "metadata": {
    "timestamp": "2026-01-18T16:18:43.416620Z",
    "run_id": "20260118_081514",
    "mode": "wildcard",
    
    "consensus_relays": 3123,
    "tested_relays": 2612,
    "relay_unreachable": 511,
    
    "success": 2580,
    "dns_fail": 29,
    "timeout": 2,
    "wrong_ip": 1,
    "socks_error": 0,
    "network_error": 0,
    "error": 0,
    "exception": 0,
    "unknown": 0,
    
    "dns_success_rate_percent": 98.77,
    "reachability_success_rate_percent": 83.63,
    
    "timing": {
      "total": { "avg_ms": 22284, "min_ms": 64, "max_ms": 45005, "p50_ms": 21655, "p95_ms": 42136, "p99_ms": 44336 }
    },
    
    "circuit_failure_reasons": {
      "circuit_timeout": 312,
      "relay_connect_failed": 156,
      "relay_resource_limit": 23,
      "circuit_destroyed": 15,
      "circuit_failed": 5
    }
  },
  
  "results": [
    {
      "exit_fingerprint": "E1134F39...",
      "exit_nickname": "JohandExit",
      "exit_address": "194.32.107.14",
      "tor_metrics_url": "https://metrics.torproject.org/rs.html#details/...",
      "status": "success",
      "circuit_reason": null,
      "query_domain": "...",
      "expected_ip": "64.65.4.1",
      "resolved_ip": "64.65.4.1",
      "timing": { "total_ms": 25868 },
      "error": null,
      "timestamp": 1768753017.76,
      "run_id": "20260118_081514",
      "mode": "wildcard",
      "first_hop": "4ECE9D36...",
      "attempt": 1,
      "consecutive_failures": 0
    },
    {
      "exit_fingerprint": "ABC12345...",
      "exit_nickname": "UnreachableRelay",
      "exit_address": "1.2.3.4",
      "tor_metrics_url": "https://metrics.torproject.org/rs.html#details/...",
      "status": "relay_unreachable",
      "circuit_reason": "circuit_timeout",
      "query_domain": null,
      "expected_ip": null,
      "resolved_ip": null,
      "timing": null,
      "error": "Tor Circuit Error: Construction timed out",
      "timestamp": 1768753017.76,
      "run_id": null,
      "mode": null,
      "first_hop": null,
      "attempt": null,
      "consecutive_failures": 1
    }
  ],
  
  "failures": [ /* all non-success entries from results, including relay_unreachable */ ],
  "failures_by_ip": { /* grouped view of failures */ }
}
```

---

## Implementation Phases

### Phase 1: Modify exitmap to track failed circuits ✅
- [x] **File**: `/home/aeo1/exitmap/src/stats.py`
  - Add `failed_circuit_relays = {}` dict to track fingerprint → reason
  - Modify `update_circs()` to record exit fingerprint when circuit fails
  - Add method to get failed circuits data
  - **ENHANCED**: Added circuit pre-registration to capture BOTH fingerprints (exit + first_hop)

- [x] **File**: `/home/aeo1/exitmap/src/eventhandler.py`
  - Pass exit fingerprint to stats when circuit fails
  - Extract fingerprint from `circ_event.path` for failed circuits

- [x] **File**: `/home/aeo1/exitmap/src/exitmap.py`
  - **ADDED**: Register circuits after `controller.new_circuit()` returns
  - **ADDED**: Record immediate failures with `record_immediate_failure()`

### Phase 2: Export circuit failures and update error messages ✅
- [x] **File**: `/home/aeo1/exitmap/src/modules/dnshealth.py`
  - In `teardown()`, access stats and write `circuit_failures.json`
  - Include: fingerprint, reason, timestamp, **first_hop**
  - Lookup nickname/address from consensus if available
  - Update existing error messages to use `DNS Error:` prefix:
    - `SOCKS 4: ...` → `DNS Error: SOCKS 4 - ...`
    - `Timeout after...` → `DNS Error: Timeout after...`
    - `Expected X, got Y` → `DNS Error: Expected X, got Y`
  - **ADDED**: Write `scan_stats.json` with circuit counts

### Phase 3: Update aggregation script ✅
- [x] **File**: `/home/aeo1/exitmap-dns-health-deploy/scripts/aggregate_results.py`
  - Load `circuit_failures.json` from analysis directory
  - **ADDED**: Load `scan_stats.json` for accurate circuit counts
  - Create result entries with `status: "relay_unreachable"`
  - Merge into unified results array
  - Update metadata with new fields:
    - `consensus_relays`
    - `tested_relays` (rename from `total_relays`)
    - `relay_unreachable`
    - `dns_success_rate_percent` (rename from `success_rate_percent`)
    - `reachability_success_rate_percent`
    - `circuit_failure_reasons`
  - Include `relay_unreachable` in `failures` array

### Phase 4: Update shell script output ✅
- [x] **File**: `/home/aeo1/exitmap-dns-health-deploy/scripts/run-dns-validation.sh`
  - Update `read_report_summary()` to show both success rates
  - Add relay_unreachable count to summary output

### Phase 5: Update UI ✅
- [x] **File**: `/home/aeo1/exitmap-dns-health-deploy/public/index.html`
  - Add "Relay Unreachable" to metrics grid
  - Show both success rates (DNS + Reachability)
  - Include relay_unreachable in failures table
  - Show circuit_reason in error column

---

## Files to Modify (Summary)

| Repository | File | Changes |
|------------|------|---------|
| exitmap | `src/stats.py` | Track failed circuit fingerprints + reasons |
| exitmap | `src/eventhandler.py` | Pass fingerprint on circuit failure |
| exitmap | `src/modules/dnshealth.py` | Export failures JSON in teardown |
| deploy | `scripts/aggregate_results.py` | Merge circuit failures, update metadata |
| deploy | `scripts/run-dns-validation.sh` | Update summary output |
| deploy | `public/index.html` | Display new category + both rates |

---

## Testing Checklist ✅

- [x] Run exitmap and verify `circuit_failures.json` is created
- [x] Verify circuit failures have correct fingerprint and reason
- [x] **BONUS**: Verify circuit failures have first_hop fingerprint (518/518 captured!)
- [x] Verify aggregation merges DNS results + circuit failures
- [x] Verify unified `results` array contains both types
- [x] Verify metadata counts are correct
- [x] Verify both success rates calculate correctly
- [x] Verify UI displays new category
- [x] Verify relay lookup finds relay_unreachable entries
- [x] Compare total: `consensus_relays == tested_relays + relay_unreachable` ✅ 3123 = 2604 + 519

---

## Rollback Plan

If issues arise:
1. Revert exitmap changes (stats.py, eventhandler.py, dnshealth.py)
2. Revert aggregate_results.py
3. Revert index.html
4. Previous JSON structure remains compatible

---

## All Error Message Formats

### DNS Errors (relay was reached, DNS test failed)

| Status | SOCKS Code | Error Message |
|--------|------------|---------------|
| `dns_fail` | 1 | `DNS Error: SOCKS 1 - General failure` |
| `dns_fail` | 2 | `DNS Error: SOCKS 2 - Not allowed by ruleset` |
| `dns_fail` | 3 | `DNS Error: SOCKS 3 - Network unreachable` |
| `dns_fail` | 4 | `DNS Error: SOCKS 4 - Domain not found (NXDOMAIN)` |
| `dns_fail` | 5 | `DNS Error: SOCKS 5 - Connection refused` |
| `dns_fail` | 6 | `DNS Error: SOCKS 6 - TTL expired` |
| `dns_fail` | 7 | `DNS Error: SOCKS 7 - Command not supported` |
| `dns_fail` | 8 | `DNS Error: SOCKS 8 - Address type not supported` |
| `timeout` | - | `DNS Error: Timeout after 45s (first_hop=FINGERPRINT)` |
| `wrong_ip` | - | `DNS Error: Expected 64.65.4.1, got 162.159.36.12` |
| `eof_error` | - | `DNS Error: Connection closed unexpectedly` |
| `tor_connection_lost` | - | `DNS Error: Lost connection to Tor (socket gone)...` |
| `tor_connection_refused` | - | `DNS Error: Tor refused connection (may be restarting)...` |
| `hard_timeout` | - | `DNS Error: Hard timeout after 300s` |

### Tor Circuit Errors (relay was NOT reached)

| Status | Tor Reason | JSON Key | Error Message |
|--------|------------|----------|---------------|
| `relay_unreachable` | `TIMEOUT` | `circuit_timeout` | Tor Circuit Error: Construction timed out |
| `relay_unreachable` | `CONNECTFAILED` | `relay_connect_failed` | Tor Circuit Error: Could not connect to relay |
| `relay_unreachable` | `NOPATH` | `circuit_no_path` | Tor Circuit Error: No path available |
| `relay_unreachable` | `RESOURCELIMIT` | `relay_resource_limit` | Tor Circuit Error: Relay at capacity |
| `relay_unreachable` | `HIBERNATING` | `relay_hibernating` | Tor Circuit Error: Relay is hibernating |
| `relay_unreachable` | `DESTROYED` | `circuit_destroyed` | Tor Circuit Error: Circuit was closed |
| `relay_unreachable` | `FINISHED` | `circuit_finished` | Tor Circuit Error: Circuit finished normally |
| `relay_unreachable` | `OR_CONN_CLOSED` | `relay_connection_closed` | Tor Circuit Error: Connection to relay closed |
| `relay_unreachable` | `CHANNEL_CLOSED` | `channel_closed` | Tor Circuit Error: Relay channel closed unexpectedly |
| `relay_unreachable` | `IOERROR` | `io_error` | Tor Circuit Error: I/O error on connection |
| `relay_unreachable` | `TORPROTOCOL` | `tor_protocol_error` | Tor Circuit Error: Protocol violation |
| `relay_unreachable` | `INTERNAL` | `tor_internal_error` | Tor Circuit Error: Internal error |
| `relay_unreachable` | `REQUESTED` | `circuit_requested` | Tor Circuit Error: Circuit close requested |
| `relay_unreachable` | `NOSUCHSERVICE` | `no_such_service` | Tor Circuit Error: Hidden service not found |
| `relay_unreachable` | `MEASUREMENT_EXPIRED` | `measurement_expired` | Tor Circuit Error: Measurement expired |
| `relay_unreachable` | `GUARD_LIMIT_REACHED` | `guard_limit` | Tor Circuit Error: Guard circuit limit reached |
| `relay_unreachable` | Other | `circuit_failed` | Tor Circuit Error: Unknown failure (REASON) |

### Error Prefix Summary

| Prefix | Layer | Meaning |
|--------|-------|---------|
| `DNS Error:` | Application | Reached relay via Tor, DNS test had issues |
| `Tor Circuit Error:` | Network | Could not build Tor circuit to relay |

---

## Notes

- Nickname/address for unreachable relays: get from consensus via `controller.get_server_descriptor()`
- `consecutive_failures` for relay_unreachable: track across runs same as DNS failures

---

*Delete this file after implementation is complete.*
