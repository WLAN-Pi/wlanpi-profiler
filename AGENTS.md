# AGENTS.md

Guidance for coding agents working in wlanpi-profiler.

## Deliberate shortcuts

Mark any deliberate simplification that cuts a real corner with a known ceiling
(naive heuristic, phy-wide instead of per-band, global lock, O(n^2) scan) with a
`ponytail:` comment naming the ceiling and the upgrade path:

```python
# ponytail: phy-wide, not per-band; split by "Band N:" if a phy ever
# advertises HE/EHT AP on one band only.
```

Do not use any other marker (`shortcut:`, `HACK:`, `XXX:`) for this. `TODO:` is
for missing work, not for a working simplification.

Find the ledger with: `rg -n "ponytail:" profiler tests`

## Verify

- `python -m pytest tests/ -q -m "not ondevice"` (CI equivalent)
- `ruff check profiler tests && ruff format --check profiler tests`
- Interface staging changes must be verified on hardware across driver
  families (iwlwifi, ath12k, mt76/mt79xx). Unit tests assert command
  ordering (see `tests/test_interface.py`), not driver behaviour.
- rtl88XXau is explicitly out of scope for hardware verification: it is not
  tested, and missing rtl88XXau hardware results never block a change or a
  review. Keep its unit tests passing; do not request or wait for device runs.

## Interface staging rules

- Never `iw dev X set type ...` while X is admin-up; mac80211 returns -EBUSY on
  every driver except iwlwifi. Change iftype only after `ip link set X down`.
- hostapd performs the managed->AP switch itself; do not pre-empt it.
- Gate 11ax/11be on `iw phy info` `HE Iftypes`/`EHT Iftypes: AP`; hostapd
  exits with `MLD: Not supported by the driver` otherwise.
- Read the regulatory domain for the selected phy via
  `profiler.status.parse_reg_domains`; do not grep `iw reg get` directly.
