# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Splunk dashboard collection** for Zeek (NSM) network security monitoring, focused on lateral movement detection, exfiltration hunting, and incident response. Dashboards are written in Splunk's XML format (stored as `.txt` files) or HTML.

## Deployment

There are no build or test commands. Dashboards are imported directly into a Splunk instance via the GUI or REST API. All dashboards query `index=zeek`.

**Required Splunk app dependency**: Sankey Diagram visualization app (used by `Cookie Sankey.txt`).

## Data Sources

All dashboards consume Zeek log sourcetypes:

| Sourcetype | Used by |
|---|---|
| `conn.log` | SA, Exfil, Sankey |
| `http.log` | HTTP, Exfil, Sankey |
| `dns.log` | DNS, Exfil |
| `smb_files.log`, `smb_mapping.log`, `smb_cmd.log` | SMB |
| `dce_rpc.log` | DCE-RPC, Sankey, BZAR |
| `kerberos.log`, `ntlm.log` | DCE-RPC, SMB |
| `ssl.log` | Exfil |
| `notice.log`, `intel.log` | BZAR Alerts |
| `weird.log`, `analyzer.log` | Weird |
| `dhcp.log` | SA |

## Dashboard Architecture

Every dashboard follows the same structural pattern:

```
<fieldset>  →  time range + src IP include/exclude tokens + port tokens
     ↓
Base search  →  indexed query against zeek with token substitution
     ↓
Panel searches  →  stats/timechart/table refinements
     ↓
Drilldown  →  linked detail searches
```

Tokens are passed as `$token_name$` in SPL. A known limitation: Splunk tokenizes `$` in field values too, so admin share detection in `Cookie SMB.txt` uses `match(share, "(?i)(ADMIN\$|C\$|IPC\$)")` instead of literal `$` to avoid token collision.

## SPL Conventions

- **RFC1918 detection**: `rex field=id.orig_h "^(?P<internal>10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"` to distinguish internal vs. external hosts
- **Beaconing candidates**: `stats avg(interval_sec) as avg_interval_sec by id.orig_h id.resp_h` after `streamstats` delta on connection timestamps
- **Exfil ratio**: `eval ratio=round(orig_bytes/resp_bytes, 2)` — high outbound ratios indicate asymmetric exfil
- **Timechart granularity**: 5-minute spans (`span=5m`) for trend panels; hourly for day-over-day comparisons

## Security Detection Focus

| Dashboard | Primary TTP |
|---|---|
| `01 Cookie SA.txt` | Baseline / inventory |
| `Cookie 02 DNS.txt` | DNS tunneling, DGA (T1071.004) |
| `04 HTTP.html` | C2 over HTTP, MIME mismatch (T1071.001) |
| `Cookie SMB.txt` | Lateral movement, admin shares (T1021.002) |
| `DCE-RPC.txt` | Lateral movement via named pipes (T1021.006) |
| `08 Cookies Exfil.txt` | Data exfiltration (T1041, T1048) |
| `Cookies BZAR Alerts.txt` | BZAR/MITRE ATT&CK alert correlation |
| `Cookie Sankey.txt` | Flow visualization (Src→Dst→Port, DCE-RPC named pipes) |
| `Weird.txt` | Protocol anomalies, recon signatures |
| `Jack 01.txt` | TTP quick-view (T1595, RDP brute force) |
| `Jack 02.txt` | Multi-source composite view |

High-value named pipes to monitor: `svcctl` (service control), `samr` (SAM enumeration), `lsarpc` (LSA), `atsvc` (task scheduler), `winreg` (registry), `drsuapi` (DCSync/credential dump).
