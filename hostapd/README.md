# Patched hostapd for wlanpi-profiler

**Last Updated:** 2026-09-21

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2026-09-21 | 2.12 | Bump 2.11 -> 2.12 (fixes CVE-2026-58374 / 2026-1 MLO parsing); rebase patch set; version now driven by `VERSION` |
| 2026-01-26 | 2.11 | Initial version lock with capability bypass patch |

## Version lock/pin strategy

**hostapd version:** `2.12` (see `VERSION`, the single source of truth)
**Source tarball:** `hostapd-2.12.tar.gz`
**SHA256 checksum:** `f43502561c28ba47ab77e18e1a973d07361c68cc8b14178e619bd5796b70eabd`
**Patch set:** `patches/*.patch` (applied in order by `build.sh`)
**Release date:** August 7, 2026

### Why version locked/pinned?

1. **Patch stability:** our patches touch specific lines in hostapd's 802.11 HT/VHT/HE/EHT/MLO code. Newer hostapd releases may restructure those files and break the patches.
2. **Deterministic builds:** a pinned tarball with checksum verification means every build produces the same source.
3. **Testing coverage:** all capability validation was performed against this version; newer versions require re-testing.
4. **Debian Policy:** packages should build reproducibly; version locking is standard practice.

### Version plumbing

`hostapd/VERSION` is the only place the version is written down. It drives:

- `build.sh` -> `hostapd-<version>.tar.gz` / `hostapd-<version>/`
- `build-in-container.sh`
- `.gitignore` (via the `hostapd/hostapd-2.*/` glob)

`debian/rules` is version-agnostic: it installs from the stable `hostapd/build/` output directory.

## Why we patch hostapd

Wi-Fi clients adapt the capabilities they advertise to match what the AP advertises. To make a client reveal its true capabilities, the profiler advertises maximum capabilities regardless of what the AP hardware actually supports:

- VHT160 when the hardware only supports VHT80
- 4 spatial streams when the hardware only has 2
- Beamforming when the hardware does not support it
- EHT (Wi-Fi 7) / MLE when the hardware lacks 802.11be support
- DFS/NO-IR restricted channels, for testing

The patches fall into three groups:

1. **Capability validation bypass** - `hw_features_profiler.patch` makes `hostapd_check_ht_capab()` accept configured HT/VHT/HE/EHT values instead of rejecting them against hardware.
2. **Capability overrides** - force HT/VHT/HE/EHT MCS/NSS maps, beamforming bits, extended capabilities, and 160 MHz advertising in the beacons.
3. **Wi-Fi 7 / MLD config** - add profiler-only config keywords (`mld_eml_capa_override`, `mld_mld_capa_override`, `emlsr_support`, `emlmr_support`, `mld_max_num_links`, `mld_link_id`, `mld_transition_timeout`, `mld_tid_to_link_negotiation`, `eht_nss_override`) and preserve configured MLD capabilities when building the Multi-Link element.

See `../HOSTAPD_BUILD_AND_PATCHING_GUIDE.md` for details.

## Building

### Requirements

Build dependencies (needed during package build, not on the target):

- `build-essential`
- `libssl-dev`
- `libnl-3-dev`
- `libnl-genl-3-dev`
- `pkg-config`

### Build process

```bash
cd hostapd/
bash build.sh
```

`build.sh` will:

1. Verify the SHA256 checksum of `hostapd-$(cat VERSION).tar.gz`
2. Extract the source to `hostapd-$(cat VERSION)/`
3. Apply every patch in `patches/` in order
4. Configure with required features (SAE, OWE, WPA3, 802.11ax, 802.11be)
5. Compile
6. Install `hostapd` and `hostapd_cli` to `build/`

### Build output

```
Binary location: hostapd/build/hostapd
Binary location: hostapd/build/hostapd_cli
```

`debian/rules` copies these into `/opt/wlanpi-profiler/bin/` during package installation.

### Building without host dependencies

```bash
cd hostapd/
bash build-in-container.sh
```

This runs `build.sh` inside a `debian:trixie` container.

## Upgrading hostapd version

1. Download the new release from <https://w1.fi/releases/> and record its SHA256.
2. Verify the signature (`hostapd-X.Y.tar.gz.asc`).
3. Vendor the tarball: `cp hostapd-X.Y.tar.gz hostapd/ && git add -f hostapd/hostapd-X.Y.tar.gz`.
4. Update `hostapd/VERSION` and `EXPECTED_SHA256` in `build.sh`.
5. Dry-run each patch against the new source and rebase the ones that fail:
   ```bash
   tar -xzf hostapd-X.Y.tar.gz && cd hostapd-X.Y
   for p in ../patches/*.patch; do patch -p1 --dry-run < "$p"; done
   ```
6. Rebuild and run the OTA regression tests (see `tests/test_ota_*.py`).

## Debian package integration

`debian/rules` builds hostapd during package creation:

```makefile
override_dh_auto_configure:
	cd hostapd && bash build.sh

override_dh_auto_install:
	install -m 755 hostapd/build/hostapd debian/$(PACKAGE)/opt/wlanpi-profiler/bin/hostapd
	install -m 755 hostapd/build/hostapd_cli debian/$(PACKAGE)/opt/wlanpi-profiler/bin/hostapd_cli
```

This means hostapd builds **during package creation** (not on the end WLAN Pi), so the target needs no build dependencies.

## Configuration features

Standard hostapd features plus the profiler overrides above. Security: WPA2-PSK, WPA3-SAE, WPA2+WPA3 transition, 802.11w MFP. Standards: 802.11n/ac/ax/be with overridden capability advertising. Management: 802.11k/v, WMM.

## Troubleshooting

**SHA256 checksum mismatch** - re-download `hostapd-<version>.tar.gz` from <https://w1.fi/releases/> and confirm `VERSION` matches.

**Patch fails to apply** - the source changed. Rebase the failing patch against the new source (see "Upgrading hostapd version").

**libnl not found** - `sudo apt-get install libnl-3-dev libnl-genl-3-dev`.

**Hostapd binary not found** - reinstall the package: `sudo apt install --reinstall wlanpi-profiler`.

**Failed to set beacon parameters** - the driver rejected the advertised capabilities. Try a different adapter or use `--fakeap` mode.

## References

- Official releases: <https://w1.fi/releases/>
- Git repository: <https://w1.fi/cgit/hostap/>
- Build guide: <https://w1.fi/cgit/hostap/tree/hostapd/README>
- Configuration: <https://w1.fi/cgit/hostap/tree/hostapd/hostapd.conf>

## License

hostapd is BSD licensed. See `hostapd-<version>/COPYING` in the extracted source.

Our patches (`patches/*.patch`) are Copyright (c) 2026 Josh Schmelzle, BSD-3-Clause (same as wlanpi-profiler).
