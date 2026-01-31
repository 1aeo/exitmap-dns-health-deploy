# Error Messages Analysis and Categorization

## Current Error Messages in Codebase

### Category 1: DNS Errors (Relay was reached, DNS test had issues)
These errors occur AFTER successfully building a Tor circuit to the exit relay.

| Status Value | Error Message | Source File | Notes |
|-------------|---------------|-------------|-------|
| `success` | (no error) | dnshealth.py | DNS resolution succeeded |
| `wrong_ip` | `DNS Error: Expected {ip}, got {ip}` | dnshealth.py | DNS hijacking detected |
| `dns_fail` | `DNS Error: SOCKS 4 - Domain not found (NXDOMAIN)` | dnshealth.py | Relay's DNS can't resolve |
| `socks_error` | `DNS Error: SOCKS {code} - {message}` | dnshealth.py | Generic SOCKS error |
| `timeout` | `DNS Error: Timeout after {N}s (first_hop={fp})` | dnshealth.py | DNS query timed out |
| `hard_timeout` | `DNS Error: Hard timeout after {N}s (first_hop={fp})` | dnshealth.py | Probe exceeded max time |
| `eof_error` | `DNS Error: Connection closed unexpectedly (first_hop={fp})` | dnshealth.py | Connection dropped |
| `exception` | `{ExceptionType}: {message}` | dnshealth.py | Unhandled Python exception |

#### SOCKS Error Sub-codes (all prefix: `DNS Error: SOCKS {N} -`)
| Code | Status | Message |
|------|--------|---------|
| 1 | `socks_general_failure` | General failure |
| 2 | `socks_ruleset_blocked` | Not allowed by ruleset |
| 3 | `network_unreachable` | Network unreachable |
| 4 | `dns_fail` | Domain not found (NXDOMAIN) |
| 5 | `connection_refused` | Connection refused |
| 6 | `ttl_expired` | TTL expired |
| 7 | `socks_command_unsupported` | Command not supported |
| 8 | `socks_address_unsupported` | Address type not supported |

### Category 2: Tor Circuit Errors (Relay was NOT reached)
These errors occur when trying to build a Tor circuit to the exit relay.

| Status Value | Tor Reason | Error Message | Source File |
|-------------|------------|---------------|-------------|
| `relay_unreachable` | `TIMEOUT` | `Tor Circuit Error: Construction timed out` | stats.py |
| `relay_unreachable` | `CONNECTFAILED` | `Tor Circuit Error: Could not connect to relay` | stats.py |
| `relay_unreachable` | `NOPATH` | `Tor Circuit Error: No path available` | stats.py |
| `relay_unreachable` | `RESOURCELIMIT` | `Tor Circuit Error: Relay at capacity` | stats.py |
| `relay_unreachable` | `HIBERNATING` | `Tor Circuit Error: Relay is hibernating` | stats.py |
| `relay_unreachable` | `DESTROYED` | `Tor Circuit Error: Circuit was closed` | stats.py |
| `relay_unreachable` | `FINISHED` | `Tor Circuit Error: Circuit finished normally` | stats.py |
| `relay_unreachable` | `OR_CONN_CLOSED` | `Tor Circuit Error: Connection to relay closed` | stats.py |
| `relay_unreachable` | `CHANNEL_CLOSED` | `Tor Circuit Error: Relay channel closed unexpectedly` | stats.py |
| `relay_unreachable` | `IOERROR` | `Tor Circuit Error: I/O error on connection` | stats.py |
| `relay_unreachable` | `TORPROTOCOL` | `Tor Circuit Error: Protocol violation` | stats.py |
| `relay_unreachable` | `INTERNAL` | `Tor Circuit Error: Internal error` | stats.py |
| `relay_unreachable` | `REQUESTED` | `Tor Circuit Error: Circuit close requested` | stats.py |
| `relay_unreachable` | `NOSUCHSERVICE` | `Tor Circuit Error: Hidden service not found` | stats.py |
| `relay_unreachable` | `MEASUREMENT_EXPIRED` | `Tor Circuit Error: Measurement expired` | stats.py |
| `relay_unreachable` | `GUARD_LIMIT_REACHED` | `Tor Circuit Error: Guard circuit limit reached` | stats.py |
| `relay_unreachable` | (other) | `Tor Circuit Error: Unknown failure ({reason})` | stats.py |
| `relay_unreachable` | `CREATION_FAILED` | `Tor Circuit Error: Failed to create circuit ({error})` | stats.py |

### Category 3: Infrastructure Errors (Local Tor process issues) ⚠️ PROBLEMATIC
These are currently MISLABELED as "DNS Error" but are actually local infrastructure issues.

| Status Value | Current Error Message | Issue |
|-------------|----------------------|-------|
| `tor_connection_refused` | `DNS Error: Tor refused connection (may be restarting)...` | **WRONG PREFIX** - Not a DNS error |
| `tor_connection_lost` | `DNS Error: Lost connection to Tor (socket gone)...` | **WRONG PREFIX** - Not a DNS error |

---

## Proposed Unified Error Structure

### Three Categories with Consistent Prefixes

| Category | Prefix | Meaning | Relay Tested? |
|----------|--------|---------|---------------|
| **DNS Error** | `DNS Error:` | Reached relay, DNS test had issues | Yes |
| **Tor Circuit Error** | `Tor Circuit Error:` | Could not build circuit to relay | No |
| **Infrastructure Error** | `Infra Error:` | Local Tor process issues | No |

### Proposed Changes to dnshealth.py

```python
# CURRENT (wrong)
status = "tor_connection_refused"
error_msg = "DNS Error: Tor refused connection (may be restarting)..."

# PROPOSED (correct)
status = "tor_connection_refused"
error_msg = "Infra Error: Local Tor refused connection (may be restarting)"
```

```python
# CURRENT (wrong)
status = "tor_connection_lost"
error_msg = "DNS Error: Lost connection to Tor (socket gone)..."

# PROPOSED (correct)
status = "tor_connection_lost"  
error_msg = "Infra Error: Lost connection to local Tor (socket gone)"
```

---

## Complete Proposed Error Table

### DNS Errors (Relay reached, DNS test performed)

| Status | Error Message | Troubleshooting |
|--------|---------------|-----------------|
| `wrong_ip` | `DNS Error: Expected {expected}, got {actual}` | Relay may be hijacking DNS or using a resolver that returns different IPs |
| `dns_fail` | `DNS Error: SOCKS 4 - Domain not found (NXDOMAIN)` | Relay's DNS resolver cannot resolve the domain |
| `timeout` | `DNS Error: Timeout after {N}s (first_hop={fp})` | DNS resolution took too long; relay or its resolver may be slow |
| `hard_timeout` | `DNS Error: Hard timeout after {N}s (first_hop={fp})` | Total probe time exceeded; may indicate stuck connection |
| `eof_error` | `DNS Error: Connection closed unexpectedly (first_hop={fp})` | The relay or intermediate node dropped the connection |
| `socks_error` | `DNS Error: SOCKS {code} - {message} (first_hop={fp})` | SOCKS protocol error during DNS resolution |
| `exception` | `DNS Error: {ExceptionType}: {message}` | Unexpected error during DNS test |

### Tor Circuit Errors (Could not reach relay)

| Status | Circuit Reason | Error Message | Troubleshooting |
|--------|---------------|---------------|-----------------|
| `relay_unreachable` | `TIMEOUT` | `Tor Circuit Error: Construction timed out` | Relay may be offline or overloaded |
| `relay_unreachable` | `CONNECTFAILED` | `Tor Circuit Error: Could not connect to relay` | Relay's ORPort may be unreachable |
| `relay_unreachable` | `RESOURCELIMIT` | `Tor Circuit Error: Relay at capacity` | Relay is overloaded, try again later |
| `relay_unreachable` | `HIBERNATING` | `Tor Circuit Error: Relay is hibernating` | Relay is in low-bandwidth mode |
| `relay_unreachable` | `DESTROYED` | `Tor Circuit Error: Circuit was closed` | Circuit was terminated by a node in the path |
| `relay_unreachable` | `OR_CONN_CLOSED` | `Tor Circuit Error: Connection to relay closed` | Network issue between nodes |
| `relay_unreachable` | `CHANNEL_CLOSED` | `Tor Circuit Error: Relay channel closed` | Relay closed the connection channel |
| `relay_unreachable` | `IOERROR` | `Tor Circuit Error: I/O error on connection` | Network I/O failure |
| `relay_unreachable` | `NOPATH` | `Tor Circuit Error: No path available` | No valid circuit path could be found |
| `relay_unreachable` | (other) | `Tor Circuit Error: {reason}` | See Tor control-spec for details |

### Infrastructure Errors (Local Tor issues - NOT relay issues)

| Status | Error Message | Troubleshooting |
|--------|---------------|-----------------|
| `tor_connection_refused` | `Infra Error: Local Tor refused connection` | Local Tor daemon is overloaded, restarting, or crashed. Reduce concurrent circuits or check Tor logs. |
| `tor_connection_lost` | `Infra Error: Lost connection to local Tor` | Local Tor daemon crashed or SOCKS socket was removed. Check Tor logs and restart if needed. |

---

## Implementation Changes Required

### 1. Update dnshealth.py error messages

```python
# Line 326-329: Change from DNS Error to Infra Error
except FileNotFoundError:
    status = "tor_connection_lost"
    error_msg = _fmt_with_hop(
        "Infra Error: Lost connection to local Tor (socket gone)",
        first_hop)

# Line 331-336: Change from DNS Error to Infra Error  
except ConnectionRefusedError:
    status = "tor_connection_refused"
    error_msg = _fmt_with_hop(
        "Infra Error: Local Tor refused connection (may be overloaded or restarting)",
        first_hop)
```

### 2. Update aggregate_results.py to handle infrastructure errors

Already done in previous commits - infrastructure errors are now tracked separately in:
- `infra_tor_refused`
- `infra_tor_lost`

And excluded from `tested_relays` count since these relays were never actually tested.

---

## Summary

| Error Type | Count | Prefix | Relay Tested? | Counted In |
|------------|-------|--------|---------------|------------|
| DNS Errors | 8+ types | `DNS Error:` | Yes | `tested_relays`, `dns_*` fields |
| Circuit Errors | 17 types | `Tor Circuit Error:` | No | `unreachable_relays`, `circuit_*` fields |
| Infra Errors | 2 types | `Infra Error:` | No | `infra_*` fields (new) |
