# Changelog

## v1.0.0 - Stable

### Architecture
- Introduced a clean event-driven orchestrator in `net_audit.py`.
- Added modular core libraries: runtime state, logger, task loader, correlator, Telegram control.
- Added robust task compatibility layer (legacy and v4 signatures).

### Security and Detection Quality
- Reworked legacy tasks (`net`, `domain`, `dns`, `udp`, `presec`, `hygiene`) for:
  - lower false-positive rates
  - explicit policy-based severity
  - bounded execution time
- Added new fast tasks:
  - `net_discovery`, `passive_scan`, `dhcp_rogue`, `vlan_8021x`, `lldp_map`,
  - `mitm_detect`, `tor`, `tldcheck`, `streaming`, `dns_tunnelling`,
  - `check_network_doh_dot_policy`.
- Added policy controls in config:
  - `dns_plaintext_forbidden`
  - `doh_dot_forbidden`
  - `enable_snmp_default_check`

### Operations
- Runtime artifacts standardized under `/var/log/net_audit` with fallback to `qp/runtime`.
- Alert dispatch now honors `[Alerts]` severity switches.
- Telegram control commands improved with persistent overrides.

### Documentation
- Updated `README.md` with policy-driven operation, anti-false-positive guidance,
  Telegram troubleshooting, and stable release workflow.
