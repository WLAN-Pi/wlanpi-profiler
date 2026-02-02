# Patched hostapd for wlanpi-profiler

**Last Updated:** 2026-01-26 

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-26 | 2.11 (locked) | Initial version lock with capability bypass patch |

## Version lock/pin strategy

**hostapd version:** `2.11` (LOCKED)  
**Source tarball:** `hostapd-2.11.tar.gz`  
**SHA256 checksum:** `2b3facb632fd4f65e32f4bf82a76b4b72c501f995a4f62e330219fe7aed1747a`  
**Patch file:** `hostapd_profiler.patch`  
**Release date:** July 20, 2024  

### Why version locked/pinned?

We maintain a specific version of hostapd because:

1. **Patch stability:** Our patch modifies `src/ap/hw_features.c` at specific line numbers. Future hostapd releases may restructure this file, breaking our patch.

2. **Deterministic builds:** Using a locked version with checksum verification ensures every build produces identical binaries.

3. **Testing coverage:** All validation was performed against hostapd 2.11. Older or newer versions would require re-testing.

4. **Debian Policy:** Debian packages should build reproducibly. Version locking is standard practice.

## What the patch Does

**File Modified:** `src/ap/hw_features.c`  
**Function:** `hostapd_check_ht_capab()`  
**Line:** 730  

### Original behavior

```c
// Line 744-755 (original code)
if (!ieee80211n_supported_ht_capab(iface))
    return -1;  // Rejects config if HT caps exceed hardware
if (!ieee80211ac_supported_vht_capab(iface))
    return -1;  // Rejects config if VHT caps exceed hardware
```

Hostapd normally validates that configured capabilities (HT/VHT/HE/EHT) don't exceed what the Wi-Fi hardware actually supports.

### Patched behavior

```c
// Line 730 (patched)
if (iface->conf->ieee80211n) {
    hostapd_logger(iface->hostapd, NULL, HOSTAPD_MODULE_IEEE80211,
        HOSTAPD_LEVEL_INFO,
        "PROFILER: Bypassing HT/VHT/HE capability validation - using config values");
    return 0;  // Accept ANY capability values from config
}
```

The patch bypasses hardware validation entirely, allowing us to advertise:

- **VHT160** when hardware only supports VHT80
- **4 spatial streams** when hardware only has 2
- **Beamforming** when hardware doesn't support it
- **EHT (Wi-Fi 7)** when hardware lacks 802.11be support

### Why this matters

Wi-Fi clients **adapt their capabilities** to match what the AP advertises. By advertising maximum capabilities, we cause clients to reveal their true capabilities in association requests.

**Example:**

- iPhone with VHT160 support connecting to VHT80-only AP → reveals VHT80 only
- Same iPhone connecting to our patched hostapd with VHT160 → reveals VHT160 ✓

This is **critical for understanding client capabilities**.

## Building

### Requirements

Build dependencies (needed during package build, NOT on target):

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

The build script will:

1. Verify SHA256 checksum of source tarball
2. Extract hostapd-2.11 source
3. Apply `hostapd_profiler.patch`
4. Configure with required features (SAE, WPA3, 802.11ax, 802.11be)
5. Compile multi-threaded
6. Output binary at `hostapd-2.11/hostapd/hostapd`

### Build output

```
Binary location: hostapd-2.11/hostapd/hostapd
Binary size: ~7.1MB (unstripped) or ~2.5MB (stripped)
```

The binary is installed to `/opt/wlanpi-profiler/bin/hostapd_profiler` during package installation.

## Debian package integration

The build is integrated into the debian package via `debian/rules`:

```makefile
override_dh_auto_build:
    # Build Python package
    dh_auto_build
    
    # Build patched hostapd
    cd hostapd && bash build.sh
    
override_dh_auto_install:
    dh_auto_install
    
    # Install hostapd binary
    install -D -m 755 hostapd/hostapd-2.11/hostapd/hostapd \
        debian/wlanpi-profiler/opt/wlanpi-profiler/bin/hostapd_profiler
```

This means:

- Hostapd builds **during package creation** (not on the end WLAN Pi)
- No build dependencies needed on target system
- Users get pre-compiled binary ready to use
- Faster installation (~1 second vs ~5 minutes + dev depends bloat if building on device)

## Upgrading hostapd version

**WARNING:** Only upgrade if absolutely necessary (security fix, critical bug, etc.)

If upgrading to a newer hostapd version:

### Step 1: Download new source

```bash
cd hostapd/
wget https://w1.fi/releases/hostapd-X.Y.tar.gz
sha256sum hostapd-X.Y.tar.gz  # Record this
```

### Step 2: Test patch

```bash
tar -xzf hostapd-X.Y.tar.gz
cd hostapd-X.Y/hostapd
patch -p2 < ../../hostapd_profiler.patch
```

**Expected:** Patch may fail if `hw_features.c` structure changed.

### Step 3: Manual patch

If patch fails, manually edit `src/ap/hw_features.c`:

1. Find the `hostapd_check_ht_capab()` function
2. Locate the hardware validation checks:
   ```c
   if (!ieee80211n_supported_ht_capab(iface))
       return -1;
   ```
3. Add bypass logic BEFORE these checks:
   ```c
   if (iface->conf->ieee80211n) {
       hostapd_logger(iface->hostapd, NULL, HOSTAPD_MODULE_IEEE80211,
           HOSTAPD_LEVEL_INFO,
           "PROFILER: Bypassing HT/VHT/HE capability validation");
       return 0;
   }
   ```

### Step 4: Regenerate patch

```bash
# After manual edits, regenerate patch
cd hostapd/
diff -Naur hostapd-X.Y.orig/ hostapd-X.Y/ > hostapd_profiler_vX.Y.patch
```

### Step 5: Update build script

Edit `build.sh`:

```bash
TARBALL="hostapd-X.Y.tar.gz"
PATCH="hostapd_profiler_vX.Y.patch"
EXPECTED_SHA256="new_checksum_here"
```

### Step 6: Test thoroughly

Before deploying:

1. **Build test:** Does it compile cleanly?
2. **Startup test:** Does hostapd start without errors?
3. **Capability test:** Do fake capabilities appear in beacons?
4. **Client test:** Does iPhone reveal VHT160 when connecting?
5. **Integration test:** Does profiler work end-to-end?

### Step 7: Update documentation

- Update this file with new version
- Update `docs/AP_MODE_INTEGRATION_PLAN.md`
- Document any behavior changes
- Update debian/changelog

## Configuration features

The patched hostapd supports all standard features plus:

### Security

- WPA2-PSK (AES-CCMP)
- WPA3-SAE (Personal)
- WPA2+WPA3 transition mode
- Management Frame Protection (MFP/802.11w)

### Wi-Fi standards

- 802.11n (HT) with fake capabilities
- 802.11ac (VHT) with fake VHT160, beamforming, etc.
- 802.11ax (HE) with full Wi-Fi 6 support
- 802.11be (EHT) with Wi-Fi 7 capabilities

### Management
- 802.11k (RRM)
- 802.11v (WNM/BSS Transition)
- WMM (QoS)

## Troubleshooting

### Build failures

**Error: SHA256 checksum mismatch**

```
Expected: 2b3facb632fd4f65e32f4bf82a76b4b72c501f995a4f62e330219fe7aed1747a
Got:      <different hash>
```

**Solution:** Re-download `hostapd-2.11.tar.gz` from https://w1.fi/releases/

**Error: Patch fails to apply**

```
Hunk #1 FAILED at 730
```

**Solution:** The source was modified. Verify you're using exact hostapd 2.11 release.

**Error: libnl not found**

```
Package libnl-3.0 was not found
```

**Solution:** Install build dependencies:

```bash
sudo apt-get install libnl-3-dev libnl-genl-3-dev
```

### Runtime issues

**Error: Patched hostapd not found**

```
FileNotFoundError: /opt/wlanpi-profiler/bin/hostapd_profiler
```

**Solution:** Binary wasn't installed. Reinstall package:

```bash
sudo apt install --reinstall wlanpi-profiler
```

**Error: Failed to set beacon parameters**

```
Could not set beacon parameters
nl80211: Beacon set failed: -22 (Invalid argument)
```

**Solution:** Driver rejected the fake capabilities. This can happen with:

- Very old drivers
- USB Wi-Fi adapters with limited feature sets
- Drivers with strict validation

**Workaround:** Use regular fakeAP mode (no --ap-mode flag)

## References

### Source

- **Official releases:** https://w1.fi/releases/
- **Git repository:** https://w1.fi/cgit/hostap/
- **Mailing list:** hostap@lists.infradead.org

### Documentation

- **Build guide:** https://w1.fi/cgit/hostap/tree/hostapd/README
- **Configuration:** https://w1.fi/cgit/hostap/tree/hostapd/hostapd.conf
- **nl80211 API:** https://wireless.wiki.kernel.org/en/developers/documentation/nl80211

## License

hostapd is licensed under BSD license. See `hostapd-2.11/COPYING` for details.

Our patch (`hostapd_profiler.patch`) is:
- Copyright (c) 2026 Josh Schmelzle
- Licensed under BSD-3-Clause (same as wlanpi-profiler)
- Maintained by: josh@joshschmelzle.com

