# Hostapd build and patching guide

**Last Updated:** 2026-02-01 
**Hostapd version:** 2.11 (pinned)  

## Table of contents

1. [Overview](#overview)
2. [Why we patch hostapd](#why-we-patch-hostapd)
3. [Patch files](#patch-files)
4. [Build process](#build-process)
5. [Config options required](#config-options-required)
6. [Troubleshooting](#troubleshooting)
7. [Adding new patches](#adding-new-patches)

## Overview

The profiler uses a **heavily patched version of hostapd 2.11** to:

1. **Bypass hardware capability validation** - Advertise capabilities beyond what Wi-Fi hardware supports
3. **Add config options** - Support EHT/MLD/EML parameters for Wi-Fi 7 profiling
4. **Override driver capabilities** - Force maximum capability advertisement regardless of driver support

**Critical note:**

The hostapd source (`hostapd-2.11/`) is **NOT tracked by git** (it's in `.gitignore`).  
Rather the source is extracted fresh on every build from `hostapd-2.11.tar.gz` and patched automatically.

---

## Why we patch hostapd

### Problem 1: Hardware validation prevents capability advertising

**Vanilla hostapd behavior:**

```c
// hostapd validates caps against hardware
if (!ieee80211n_supported_ht_capab(iface))
    return -1;  // Rejects VHT160 if hardware only has VHT80
```

**Our patched behavior:**

```c
// Bypass validation entirely
if (iface->conf->ieee80211n) {
    hostapd_logger(..., "PROFILER: Bypassing capability validation");
    return 0;  // Accept ANY capability values
}
```

**Why this matters:**

Wi-Fi clients **adapt their capabilities to match the AP**. If we advertise VHT80, clients with VHT160 support will only reveal VHT80. By advertising maximum capabilities, clients reveal their true capabilities.

### Problem 2: DFS validation prevents 160 MHz testing

**The issue:**

- 160 MHz on channel 36 spans 5170-5330 MHz
- Channels 52-64 are DFS (radar) channels  
- Hostapd's DFS validation: `could not get valid channel`

**Our patch:**

```c
// src/ap/dfs.c - dfs_set_valid_channel()
wpa_printf(MSG_INFO, "PROFILER: DFS validation disabled - using configured channel");
return 0;  // Skip all DFS checks
```

We also advertise fake channel information in other patches.

### Problem 3: Missing config options for Wi-Fi 7

**Template uses these config options:**

```
emlsr_support=1
emlmr_support=1
mld_max_num_links=2
eht_nss_override=4
interworking=1
```

**Hostapd 2.11 doesn't parse these by default!**

We add config parsing + struct members + capability override logic.

## Patch files

### Location

`hostapd/patches/`

### Applied patches (in order)

| Patch File | Purpose | Target File | Method |
|------------|---------|-------------|---------|
| `profiler_version_string.patch` | Add "TESTING ONLY" warning to `-v` output | `hostapd/main.c` | `patch -p1` |
| `disable_dfs_checks.patch` | Bypass DFS validation for 160 MHz testing | `src/ap/dfs.c` | `patch -p1` |
| **(sed script)** | Add MLD/EML struct members | `src/ap/ap_config.h` | `sed -i` |
| **(sed script)** | Add config parsing for MLD/EML/EHT options | `hostapd/config_file.c` | `sed -i` |
| **(sed script)** | Override driver MLD capabilities | `src/ap/ap_drv_ops.c` | `sed -i` |
| `hostapd_eht_mac_caps.patch` | Force maximum EHT MAC capabilities | `src/ap/ieee802_11_eht.c` | `patch -p1` |
| `hostapd_ext_cap_scs.patch` | Override SCS extended capability | `src/ap/ieee802_11_shared.c` | `patch -p1` |
| `hostapd_ext_cap_twt.patch` | Override TWT extended capability | `src/ap/ieee802_11_shared.c` | `patch -p1` |
| `hostapd_ht_txbf.patch` | Override HT beamforming capabilities | `src/ap/ieee802_11_ht.c` | `patch -p1` |
| `hostapd_mld_caps.patch` | Override MLD capabilities from driver | `src/ap/ap_drv_ops.c` | `patch -p1` |

### Why some use `sed` instead of patches

**Problem:** Patch files with complex indentation/whitespace fail with "malformed patch" errors.

**Solution:** Use `sed -i` for inline code insertions:

```bash
sed -i '/eht_bw320_offset = atoi(pos);/a\
\	} else if (os_strcmp(buf, "emlsr_support") == 0) {\
\		int val = atoi(pos);\
\		...' hostapd/config_file.c
```

**Advantages:**

- No whitespace/tab issues
- Works with any line ending format
- Easier to maintain for large insertions

**Disadvantages:**

- Less portable than patch files
- Harder to review diffs

YOLO.

## Build process

### Overview

```
build-package-native.sh
  └─> Builds Debian Bookworm container
      └─> hostapd/build.sh
          ├─> Extract hostapd-2.11.tar.gz
          ├─> Apply patches (2 files + 3 sed scripts)
          ├─> Configure (.config with 13 features)
          └─> Compile (make -j)
```

### Step-by-step

#### 1. Container setup

```bash
docker build -f- -t wlanpi-profiler-build-bookworm:latest . <<'EOF'
FROM debian:bookworm
RUN apt-get update && apt-get install -y \
    build-essential \
    debhelper \
    dh-python \
    python3-all \
    python3-setuptools \
    libssl-dev \
    libnl-3-dev \
    libnl-genl-3-dev \
    pkg-config
EOF
```

**Why Bookworm?**

- WLAN Pi runs Debian Bookworm (glibc 2.36)
- Building on Fedora 43 (glibc 2.38) creates incompatible binaries
- `error while loading shared libraries: libc.so.6: version GLIBC_2.38 not found`

#### 2. Hostapd extraction

```bash
cd hostapd/
tar -xzf hostapd-2.11.tar.gz
cd hostapd-2.11/
```

#### 3. Apply patches

```bash
# Patch 1: Version string
patch -p1 < ../patches/profiler_version_string.patch

# Patch 2: DFS bypass
patch -p1 < ../patches/disable_dfs_checks.patch

# Sed Script 1: Add struct members to ap_config.h
sed -i '/punct_acs_threshold;/a\
\	u16 mld_eml_capa_override;\
\	u16 mld_mld_capa_override;\
\	u8 eht_nss_override;\
\	bool mld_eml_capa_set;\
\	bool mld_mld_capa_set;\
\	bool eht_nss_override_set;' src/ap/ap_config.h

# Sed Script 2: Add config parsing to config_file.c  
sed -i '/eht_bw320_offset = atoi(pos);/a\
\	} else if (os_strcmp(buf, "emlsr_support") == 0) {\
\		...(40 lines of config parsing)...' hostapd/config_file.c

# Sed Script 3: Add capability override to ap_drv_ops.c
sed -i '/&iface->mld_mld_capa);/a\
\	if (conf->mld_eml_capa_set) {\
\		iface->mld_eml_capa = conf->mld_eml_capa_override;\
\		...' src/ap/ap_drv_ops.c

# Patches 3-N: Apply capability override patches
for patch in ../patches/hostapd_*.patch; do
    patch -p1 < "$patch" || true  # Continue on failure
done
```

#### 4. Configure build

```bash
cd hostapd/
cp defconfig .config

# Enable 802.11n/ac (disabled by default)
sed -i 's/#CONFIG_IEEE80211N=y/CONFIG_IEEE80211N=y/' .config
sed -i 's/#CONFIG_IEEE80211AC=y/CONFIG_IEEE80211AC=y/' .config

# Add required features
cat >> .config <<EOF
CONFIG_LIBNL32=y
CONFIG_SAE=y
CONFIG_OWE=y
CONFIG_IEEE80211AX=y
CONFIG_IEEE80211BE=y
CONFIG_MBO=y
CONFIG_WPA3_SAE=y
CONFIG_IEEE80211W=y
CONFIG_WNM=y
CONFIG_IEEE80211R=y
CONFIG_INTERWORKING=y
CONFIG_HS20=y
EOF
```

#### 5. Compile

```bash
make -j$(nproc)
```

**Output:** `hostapd-2.11/hostapd/hostapd` (1.5 MB)

#### 6. Package integration

```bash
# debian/rules copies binary into package
install -D -m 755 hostapd/hostapd-2.11/hostapd/hostapd \
    debian/wlanpi-profiler/opt/wlanpi-profiler/bin/hostapd
```

## Config options required

### Critical options 

These are **required** for profiler's config templates to work:

| CONFIG Option | Purpose | Template usage |
|---------------|---------|----------------|
| `CONFIG_IEEE80211AX=y` | Wi-Fi 6 (HE) support | `ieee80211ax=1` |
| `CONFIG_IEEE80211BE=y` | Wi-Fi 7 (EHT) support | `ieee80211be=1`, MLD options |
| `CONFIG_IEEE80211R=y` | Fast Transition (FT) | `mobility_domain=`, FT options |
| `CONFIG_INTERWORKING=y` | 802.11u Hotspot 2.0 | `interworking=1`, `access_network_type=` |
| `CONFIG_HS20=y` | Hotspot 2.0 (Passpoint) | (dependency of INTERWORKING) |

**Without these:** Hostapd startup fails with `unknown configuration item` errors.

### Recommended options

| CONFIG Option | Purpose |
|---------------|---------|
| `CONFIG_SAE=y` | WPA3-SAE authentication |
| `CONFIG_OWE=y` | Opportunistic Wireless Encryption |
| `CONFIG_MBO=y` | Multi-Band Operation |
| `CONFIG_WPA3_SAE=y` | WPA3 security |
| `CONFIG_IEEE80211W=y` | Management Frame Protection |
| `CONFIG_WNM=y` | Wireless Network Management |
| `CONFIG_LIBNL32=y` | Netlink 3.2 library (required for nl80211) |

### How to verify

```bash
# Check binary has config keywords
strings /opt/wlanpi-profiler/bin/hostapd | grep -E '^(interworking|emlsr_support|mld_max_num_links)$'

# Expected output:
interworking
emlsr_support  
mld_max_num_links
```

## Troubleshooting

### Build fails: "Patch does not apply"

**Symptom:**

```
patch: **** malformed patch at line 17
patch: **** malformed patch at line 56: +	static int profiler_eht_phy_logged = 0;
```

**Cause:** Whitespace/tab/line-ending mismatch in patch file, or complex patch structure

**Solution:** See [Common Patch Issues and Solutions](#common-patch-issues-and-solutions) below

### Build fails: "struct has no member named 'mld_eml_capa_override'"

**Symptom:**

```
config_file.c:5097:29: error: 'struct hostapd_config' has no member named 'mld_eml_capa_override'
```

**Cause:** Struct members weren't added to `ap_config.h`

**Solution:** Check that sed script for `ap_config.h` ran successfully:

```bash
grep "mld_eml_capa_override" hostapd/hostapd-2.11/src/ap/ap_config.h
# Should show: u16 mld_eml_capa_override;
```

### Hostapd fails: "unknown configuration item"

**Symptom:**

```
Line 80: unknown configuration item 'emlsr_support'
```

**Cause:** Config option not compiled into hostapd

**Solution:**

1. Check binary: `strings hostapd | grep emlsr_support`  
2. If missing, rebuild with sed script applied
3. Verify `.config` has `CONFIG_IEEE80211BE=y`

### Runtime: "DFS validation disabled" not appearing

**Symptom:** No "PROFILER: DFS validation disabled" in hostapd logs

**Cause:** DFS patch not applied

**Solution:**

```bash
# Verify patch applied
grep "PROFILER: DFS validation disabled" hostapd/hostapd-2.11/src/ap/dfs.c

# If missing, check patch was applied during build
grep "Applying disable_dfs_checks.patch" /tmp/build.log
```

### Hostapd logs missing

**Symptom:** Can't see hostapd output in profiler logs

**Solution:** Hostapd log streaming was added to `profiler/hostapd_manager.py`:

```python
# Logs appear as:
# [HOSTAPD] wlan0: AP-ENABLED
# [HOSTAPD] PROFILER: DFS validation disabled
# [HOSTAPD-ERR] Line 32: unknown configuration item...
```

Check with:

```bash
sudo journalctl -u wlanpi-profiler -f | grep HOSTAPD
```

## Common patch issues and solutions

This section documents **specific patching challenges** encountered during development and their proven solutions. These issues occur repeatedly when creating patches for hostapd.

### Issue 1: "Malformed Patch" errors from large hunks

**Symptom:**

```bash
patch: **** malformed patch at line 56: +	static int profiler_eht_phy_logged = 0;
patch: **** malformed patch at line 24:  
```

**Root Cause:**

GNU patch 2.8 has difficulty with patches that:

1. Add more than ~20 lines in a single hunk
2. Have blank context lines (` ` followed by newline) after added content
3. Mix tabs and spaces in context lines

**Example of Problematic Patch:**

```diff
@@ -173,6 +190,26 @@
 		cap->phy_cap[EHT_PHYCAP_MU_BEAMFORMER_IDX] &=
 			~EHT_PHYCAP_MU_BEAMFORMER_MASK;
 
+	/* Add 20+ lines of code here */
+	cap->phy_cap[0] |= (1 << 3);
+	cap->phy_cap[1] |= (1 << 1);
+	...
+	cap->phy_cap[8] |= (1 << 4);
+
 	pos = cap->optional;
 
 	mcs_nss_len = ieee80211_eht_mcs_set_size(mode->mode,
```

The blank context lines (` ` and ` `) after the additions cause patch to fail.

**Solution: Split into Multiple Smaller Patches**

**Instead of one large patch:**

```bash
hostapd_eht_caps.patch      # 90 lines, 3 hunks, FAILS
```

**Create three focused patches:**

```bash
hostapd_eht_mac_caps.patch  # MAC capabilities override
hostapd_eht_phy_caps.patch  # PHY capabilities override  
hostapd_eht_mcs_nss.patch   # MCS/NSS map override
```

**How to split:**

```bash
cd hostapd/hostapd-2.11

# 1. Extract and apply first patch manually
cp src/ap/ieee802_11_eht.c src/ap/ieee802_11_eht.c.orig

# 2. Make ONLY the first set of changes
vim src/ap/ieee802_11_eht.c  # Edit MAC capabilities section

# 3. Generate patch for just this change
diff -u src/ap/ieee802_11_eht.c.orig src/ap/ieee802_11_eht.c > ../patches/hostapd_eht_mac_caps.patch

# 4. Apply this patch to verify
rm -rf hostapd-2.11 && tar -xzf hostapd-2.11.tar.gz
cd hostapd-2.11 && patch -p1 < ../patches/hostapd_eht_mac_caps.patch

# 5. Repeat for second set of changes (PHY capabilities)
cp src/ap/ieee802_11_eht.c src/ap/ieee802_11_eht.c.orig
vim src/ap/ieee802_11_eht.c  # Edit PHY section
diff -u src/ap/ieee802_11_eht.c.orig src/ap/ieee802_11_eht.c > ../patches/hostapd_eht_phy_caps.patch
```

**Key rules for successful patches:**

1. **Keep hunks small** - Maximum 15-20 added lines per hunk
2. **Minimize context** - Only include 3-5 lines of context before/after changes
3. **Avoid blank context lines at the end** - End with actual code, not blank lines
4. **One logical change per patch** - MAC caps, PHY caps, MCS/NSS should be separate
5. **Follow naming convention** - Use `hostapd_*.patch` prefix for capability overrides (see below)

### Issue 2: Blank context lines cause failures

**Symptom:**

```bash
patch: **** malformed patch at line 26:  
```

Line 26 of your patch is just a blank context line (` ` followed by newline).

**Root Cause:**

When a patch has trailing blank context lines after additions, like:

```diff
+	cap->phy_cap[8] |= (1 << 4);
+
 	pos = cap->optional;
 
 	mcs_nss_len = ieee80211_eht_mcs_set_size(mode->mode,
```

The two context lines (` 	pos = cap->optional;` and ` `) can confuse patch.

**Solution: remove trailing context lines**

**Bad (fails):**

```diff
@@ -190,6 +190,22 @@
 		~EHT_PHYCAP_MU_BEAMFORMER_MASK;
 
+	cap->phy_cap[0] |= (1 << 3);
 	pos = cap->optional;
 
 	mcs_nss_len = ieee80211_eht_mcs_set_size(mode->mode,
```

**Good (works):**

```diff
@@ -190,6 +190,22 @@
 		~EHT_PHYCAP_MU_BEAMFORMER_MASK;
 
+	cap->phy_cap[0] |= (1 << 3);
 	pos = cap->optional;
```

Just end the hunk at the first line of context after your additions. Don't include the blank line or the function call continuation.

**IMPORTANT - Context Lines ARE required:**

The guidance above about "ending immediately after your last `+` line" is **MISLEADING**. Through extensive testing (2026-01-25), the correct format is:

**CORRECT FORMAT - Always include trailing context lines:**

```diff
+	oper->vht_op_info_chan_center_freq_seg1_idx = 50;  /* Full 160 MHz center */
+

 	/* VHT Basic MCS set comes from hw */
 	/* Hard code 1 stream, MCS0-7 is a min Basic VHT MCS rates */
 	oper->vht_basic_mcs_set = host_to_le16(0xfffc);
```

**Key rules:**

1. **Always include 2-3 trailing context lines** after your last `+` line
2. If your code ends with a blank line (`+` alone), include it
3. Follow with 2-3 lines of unchanged context from the original file
4. Each context line starts with a space (` `) followed by a tab (`\t`) and the code
5. File **must** end with exactly one newline (`\n`) after the last context line
6. **Verify hunk size** matches actual line count

**Hunk header format:**

```diff
@@ -161,6 +161,22 @@ u8 * hostapd_eid_vht_operation(...)
```
- `-161,6` = Old file starts at line 161, takes 6 lines  
- `+161,22` = New file starts at line 161, takes 22 lines (6 original + 16 added)
- **The second number MUST be exact:** count all `+` lines plus context lines in the hunk

**Mistakes:**

- Ending with no context lines → `patch: **** malformed patch at line X`
- Wrong hunk size (e.g., `+21` when should be `+22`) → `malformed patch`  
- Two newlines at EOF (from heredoc) → `malformed patch`
- Missing trailing blank line when original has one → patch fails

### Issue 3: Unicode characters break patches

**Symptom:**

Patch applies but produces garbled output, or fails with encoding errors.

**Root Cause:**

Unicode characters like μ (Greek mu) in comments:

```c
cap->phy_cap[2] |= (1 << 3);  /* Bit 19: EHT MU PPDU With 4 EHT-LTF And 0.8μs GI */
```

The `μ` is UTF-8 encoded as `0xCE 0xBC`, which can confuse some patch implementations.

**Solution: Use ASCII equivalents**

```bash
# Replace Unicode in patch files
sed -i 's/μ/u/g' hostapd/patches/hostapd_eht_caps.patch
sed -i 's/μs/us/g' hostapd/patches/hostapd_eht_caps.patch
```

**Result:**

```c
cap->phy_cap[2] |= (1 << 3);  /* Bit 19: EHT MU PPDU With 4 EHT-LTF And 0.8us GI */
```

### Issue 4: How to create a patch file 

**Problem:** Creating patch files manually often results in formatting errors.

**Solution:** Follow this process:

#### Step 1: Identify insertion point

```bash
# Find the function you're modifying
grep -n "function_name" /tmp/hostapd-2.11/src/ap/file.c

# View context around insertion point
sed -n '160,170p' /tmp/hostapd-2.11/src/ap/file.c
```

#### Step 2: Count lines carefully

Before writing the patch:

1. Count leading context lines (3 before your additions)
2. Count your `+` lines (code you're adding)
3. Count trailing context lines (2-3 after your additions)
4. **Total = context_before + added_lines + context_after**

Example:

- 3 context lines before (lines 4-6 in patch)
- 16 added lines (lines 7-22 in patch)  
- 3 context lines after (lines 23-25 in patch)
- **Hunk size = 3 + 16 + 3 = 22** → Use `@@ -161,6 +161,22 @@`

#### Step 3: Create patch file using cat (NOT heredoc for last line)

```bash
cat > hostapd/patches/new_patch.patch << 'EOF'
--- a/src/ap/file.c
+++ b/src/ap/file.c
@@ -161,6 +161,22 @@ function_signature(...)
 	existing_context_line_1
 	existing_context_line_2
 	}
+	/* Your new code starts here */
+	new_code_line_1
+	new_code_line_2
+

 	/* Original context after your addition */
 	original_line_1
EOF
# CRITICAL: Add last line separately with printf to control newline exactly
printf ' \toriginal_line_2\n' >> hostapd/patches/new_patch.patch
```

**Why this works:**

- Heredoc (`<< 'EOF'`) adds an extra newline at the end
- Using `printf` for the last line gives exact control
- One final newline is required, but not two

#### Step 4: Test the patch

```bash
cd /tmp
rm -rf hostapd-2.11
tar -xzf /path/to/hostapd-2.11.tar.gz
cd hostapd-2.11

# Apply any prerequisite patches first
patch -p1 < /path/to/earlier_patch.patch

# Test your new patch
patch -p1 --dry-run < /path/to/new_patch.patch
# If successful:
patch -p1 < /path/to/new_patch.patch
```

#### Step 5: Verify line endings

```bash
# Check last 50 bytes - should end with exactly ONE \n
tail -c 50 hostapd/patches/new_patch.patch | od -c

# Should see: ... \n
# NOT: ... \n \n
```

### Issue 5: Patch naming convention not followed

**Symptom:**

Patch exists in `hostapd/patches/` but is never applied during build. No error message shown.

**Root cause:**

The build script (`hostapd/build.sh`) applies patches using glob patterns:
- `hostapd_*.patch` - Applied in step 4 (capability overrides)
- `eht_*.patch` - Applied in step 4b (EHT operation patches)
- `mld_*.patch` - Applied in step 4c (MLD patches)

Patches not matching these patterns are silently skipped.

**Example of problem:**

```bash
# This patch was created but NEVER applied:
hostapd/patches/preserve_max_simul_links.patch  # Doesn't match any pattern!

# Fix: Rename to follow convention:
hostapd/patches/mld_preserve_max_simul_links.patch  # Matches mld_*.patch ✓
```

**How to verify patches are applied:**

```bash
./build-package-native.sh 2>&1 | grep "Applying.*your_patch_name"
# If you see "✓ Applied" after your patch name, it worked
# If you don't see your patch name at all, it's not matching the glob pattern
```

**Naming convention rules:**

- Capability override patches → `hostapd_*.patch` (e.g., `hostapd_eht_mac_caps.patch`)
- EHT operation patches → `eht_*.patch` (e.g., `eht_operation_basic_mcs_nss.patch`)  
- MLD patches → `mld_*.patch` (e.g., `mld_preserve_max_simul_links.patch`)
- Infrastructure patches → Applied individually by name in steps 1-3

### Issue 5: Patch line numbers incorrect after previous patches

**Symptom:**

```bash
Hunk #1 FAILED at 173.
Hunk #2 FAILED at 182.
```

**Root cause:**

When creating patches from an already-modified file, the line numbers reference the modified file, not the original.

**Example:**

```bash
# You applied patch 1, which added 17 lines
# Original line 173 is now at line 190

# But your new patch says:
@@ -173,6 +190,26 @@  # WRONG! Should be @@ -190,6 +190,26 @@
```

**Solution: Always generate patches from original file state**

```bash
# WRONG: Creating patch from already-modified file
cd hostapd-2.11
patch -p1 < ../patches/patch1.patch  # Applies successfully
vim src/ap/file.c  # Make more changes
diff -u original/src/ap/file.c src/ap/file.c > patch2.patch  # LINE NUMBERS WRONG!

# RIGHT: Start fresh for each patch
cd hostapd && rm -rf hostapd-2.11
tar -xzf hostapd-2.11.tar.gz
cd hostapd-2.11

# Apply existing patches FIRST
patch -p1 < ../patches/patch1.patch

# THEN make your changes
cp src/ap/file.c src/ap/file.c.backup
vim src/ap/file.c

# Generate diff from the backup (which has patch1 applied)
diff -u src/ap/file.c.backup src/ap/file.c > ../patches/patch2.patch
```

**Verify line numbers:**

```bash
# Extract fresh source
tar -xzf hostapd-2.11.tar.gz
cd hostapd-2.11

# Apply patches in sequence
patch -p1 < ../patches/patch1.patch && echo "Patch 1 OK"
patch -p1 < ../patches/patch2.patch && echo "Patch 2 OK"
```

### Issue 5: Tabs vs spaces in context lines

**Symptom:**

```bash
patch: **** malformed patch at line 15:  	pos = cap->optional;
```

**Root cause:**

C code uses tabs for indentation, but your editor converted them to spaces when creating the patch.

**Solution: Preserve tabs in patches**

```bash
# Check if tabs are present
cat -A hostapd/patches/my_patch.patch | head -20
# Look for ^I (tab character)

# If you see spaces instead of tabs, regenerate with correct settings
diff -u --preserve-tabs original.c modified.c > my_patch.patch
```

**vim settings to preserve tabs:**

```vim
:set noexpandtab
:set tabstop=8
:set shiftwidth=8
```

**Verification:**

```bash
# Context lines should have: space (diff marker) + tab (file indentation)
sed -n '15p' my_patch.patch | od -c
# Should show: space + tab + code
# 0000000   space   \t   p   o   s   ...
```

### Issue 6: Using `diff` vs `patch -p1` file paths

**Symptom:**

```bash
patch: **** Can't find file to patch at line 1
```

**Root cause:**

Patch file uses incorrect path format:

```diff
--- src/ap/ieee802_11_eht.c.orig    # WRONG
+++ src/ap/ieee802_11_eht.c         # WRONG
```

**Solution: Use `a/` and `b/` prefixes**

```diff
--- a/src/ap/ieee802_11_eht.c      # CORRECT
+++ b/src/ap/ieee802_11_eht.c      # CORRECT
```

**How to create:**

```bash
# Use git diff format (always uses a/ and b/)
diff -Naur a/src/ap/file.c b/src/ap/file.c > my.patch

# Or manually fix paths
sed -i '1s|^---|--- a/|; 2s|^+++|+++ b/|' my.patch

# Remove timestamps (optional but cleaner)
sed -i '1s/\t.*//; 2s/\t.*//' my.patch
```

### Issue 7: Generating patches with `sed` modifications

**Problem:**

You modified a file using `sed`, now you want to create a patch for it.

**Solution:**

```bash
# 1. Extract fresh source
cd hostapd && tar -xzf hostapd-2.11.tar.gz

# 2. Copy to backup
cp hostapd-2.11/src/ap/file.c hostapd-2.11/src/ap/file.c.orig

# 3. Apply your sed modification
sed -i '192 a\
\	/* My new code */\
\	cap->phy_cap[0] |= (1 << 3);' hostapd-2.11/src/ap/file.c

# 4. Generate patch
cd hostapd-2.11
diff -u src/ap/file.c.orig src/ap/file.c > ../patches/my_feature.patch

# 5. Fix paths
cd ../patches
sed -i '1s|src/ap/|a/src/ap/|; 2s|src/ap/|b/src/ap/|' my_feature.patch
sed -i '1s|\.orig||' my_feature.patch
sed -i '1s/\t.*//; 2s/\t.*//' my_feature.patch

# 6. Test application
cd ../hostapd && rm -rf hostapd-2.11 && tar -xzf hostapd-2.11.tar.gz
cd hostapd-2.11 && patch -p1 < ../patches/my_feature.patch
```

### Recommended patch creation workflow

**Step-by-step process to avoid all common issues:**

```bash
# 1. Start with clean source
cd hostapd
rm -rf hostapd-2.11
tar -xzf hostapd-2.11.tar.gz
cd hostapd-2.11

# 2. Apply any prerequisite patches
patch -p1 < ../patches/prerequisite.patch

# 3. Create backup of file you're modifying
cp src/ap/ieee802_11_eht.c src/ap/ieee802_11_eht.c.orig

# 4. Make your changes (vim, sed, whatever)
vim src/ap/ieee802_11_eht.c

# 5. Generate patch using diff
diff -u src/ap/ieee802_11_eht.c.orig src/ap/ieee802_11_eht.c > /tmp/my_patch.patch

# 6. Fix patch file paths and formatting
sed -i '1s|src/ap/|a/src/ap/|' /tmp/my_patch.patch
sed -i '2s|src/ap/|b/src/ap/|' /tmp/my_patch.patch
sed -i '1s|\.orig||' /tmp/my_patch.patch
sed -i '1s/\t.*//; 2s/\t.*//' /tmp/my_patch.patch

# 7. Remove any Unicode characters
sed -i 's/μ/u/g' /tmp/my_patch.patch

# 8. Verify patch structure
head -20 /tmp/my_patch.patch
# Should see:
# --- a/src/ap/ieee802_11_eht.c
# +++ b/src/ap/ieee802_11_eht.c
# @@ -X,Y +X,Z @@

# 9. Test application on fresh source
cd .. && rm -rf hostapd-2.11 && tar -xzf hostapd-2.11.tar.gz
cd hostapd-2.11
patch -p1 --dry-run < /tmp/my_patch.patch  # Dry run first
patch -p1 < /tmp/my_patch.patch             # Real application

# 10. If successful, save to patches directory
mv /tmp/my_patch.patch ../patches/my_feature.patch

# 11. Add to build.sh
vim ../build.sh
# Add: patch -p1 < ../patches/my_feature.patch
```

**Validation checklist:**

- [ ] Patch has `a/` and `b/` prefixes in paths
- [ ] No `.orig` in filenames
- [ ] No timestamps in first two lines
- [ ] No Unicode characters in comments
- [ ] Each hunk is < 20 added lines
- [ ] No trailing blank context lines after additions
- [ ] Line numbers reference original file (or file after previous patches)
- [ ] Tabs preserved in C code indentation
- [ ] Patch applies cleanly with `patch -p1 --dry-run`
- [ ] **Filename follows naming convention** (see issue 5 below)

---

## Adding new patches

### Option 1: Traditional patch file

**When to use:** Small, simple changes to single files

**Process:**

```bash
cd hostapd/hostapd-2.11/

# Make changes
vim src/ap/some_file.c

# Create patch (from hostapd-2.11/ directory)
git diff --no-index /dev/null src/ap/some_file.c > ../patches/my_feature.patch

# Or if comparing to original:
diff -Naur original/src/ap/some_file.c src/ap/some_file.c > ../patches/my_feature.patch
```

**Add to build.sh:**

```bash
if [ -f "../patches/my_feature.patch" ]; then
    patch -p1 < "../patches/my_feature.patch"
fi
```

### Option 2: sed script

**When to use:** Large insertions, whitespace-sensitive code, struct member additions

**Process:**

```bash
# Test sed command manually first
sed -i '/ANCHOR_LINE/a\
\	NEW CODE LINE 1\
\	NEW CODE LINE 2' src/ap/file.c

# Verify it worked
git diff src/ap/file.c

# Add to build.sh
```

**Important sed gotchas:**

- Use `\` at end of each line (except last)
- Prefix each line with `\	` for tabs
- Escape special regex chars: `[`, `]`, `*`, etc.
- Test on extracted source before adding to build.sh

### Option 3: Direct file modification

**When to use:** Only for `.config` changes, never for C code

**Example:**

```bash
# Add config option
echo "CONFIG_NEW_FEATURE=y" >> .config

# Or modify existing
sed -i 's/#CONFIG_FEATURE=y/CONFIG_FEATURE=y/' .config
```

## Patch development workflow

### 1. Extract clean source

```bash
cd hostapd/
tar -xzf hostapd-2.11.tar.gz
cp -r hostapd-2.11 hostapd-2.11-clean
```

### 2. Make changes

```bash
cd hostapd-2.11/
vim src/ap/file.c
# Make your changes
```

### 3. Test build

```bash
cd hostapd/
cp defconfig .config
# Add CONFIG options
make -j$(nproc)
./hostapd -v  # Verify changes
```

### 4. Create patch

```bash
# If using git diff:
git diff hostapd-2.11-clean/ hostapd-2.11/ > patches/my_change.patch

# If using diff:
diff -Naur hostapd-2.11-clean/src/ap/file.c hostapd-2.11/src/ap/file.c > patches/my_change.patch
```

### 5. Test patch application

```bash
rm -rf hostapd-2.11/
tar -xzf hostapd-2.11.tar.gz
cd hostapd-2.11/
patch -p1 < ../patches/my_change.patch
# Check for "patch applied successfully"
```

### 6. Integrate into build

```bash
# Add to build.sh in correct order
vim build.sh

# Test full build
rm -rf hostapd-2.11/
./build.sh
```

## Reference

### Build environment

- **Host OS:** Any (Fedora, Debian, macOS via Docker)
- **Container:** Debian Bookworm (`debian:bookworm`)
- **Target:** WLAN Pi (Debian Bookworm, glibc 2.36, ARM64)
- **Hostapd Version:** 2.11 (locked)
- **Source:** `hostapd-2.11.tar.gz` (SHA256 verified)

### Key files

| File | Purpose |
|------|---------|
| `hostapd/build.sh` | Main build orchestration script |
| `hostapd/hostapd-2.11.tar.gz` | Locked source tarball (2.11) |
| `hostapd/patches/*.patch` | Patch files for source modifications |
| `build-package-native.sh` | Top-level package build (calls hostapd/build.sh) |
| `debian/rules` | Debian package rules (copies hostapd binary) |

### Documentation

- **Main README:** `hostapd/README.md`
- **DFS patching:** `HOSTAPD_DFS_PATCHING_GUIDE.md`

### Verification commands

```bash
# Check binary version
/opt/wlanpi-profiler/bin/hostapd -v

# Check config keywords present
strings /opt/wlanpi-profiler/bin/hostapd | grep -E '^(interworking|emlsr_support)$'

# Test config file parsing
/opt/wlanpi-profiler/bin/hostapd -dd /tmp/test_config.conf

# Check logs during runtime
sudo journalctl -u wlanpi-profiler -f | grep -E 'HOSTAPD|PROFILER'
```

### Issue 6: Context lines missing leading space (CRITICAL!)

**Symptom:**
```
patch: **** malformed patch at line 26:  		pos += mcs_nss_len;
```

The patch tool reports a malformed patch at a specific line number, even though the line looks correct when viewing the file.

**Root Cause:**

Context lines in unified diff format **MUST** start with a space (` `) character. If you edit a patch file with text editors or the Write tool, leading spaces on context lines can be stripped, causing the patch to become invalid.

**The format rules:**

- Lines starting with `-` are removed from the original
- Lines starting with `+` are added to the new version  
- Lines starting with ` ` (space) are context lines (unchanged)
- **Context lines MUST have the leading space or patch fails!**

**Example of WRONG format:**

```diff
+		}
+
	pos += mcs_nss_len;    # <- Missing leading space!
	}                       # <- Missing leading space!
```

**Example of CORRECT format:**

```diff
+		}
+
 		pos += mcs_nss_len;   # <- Has leading space
 	}                        # <- Has leading space
```

**How to diagnose:**

Use `cat -A` to see all characters including spaces and tabs:

```bash
cat -A hostapd/patches/your_patch.patch | tail -10
```

Look for context lines that should start with ` ^I` (space then tab) but instead start with just `^I` (tab only).

**How to fix:**

Use `sed` to add the leading space to specific lines:

```bash
# Fix line 26 (add space before first tab)
sed -i '26s/^\t/ \t/' hostapd/patches/your_patch.patch

# Fix last line
sed -i '$s/^\t/ \t/' hostapd/patches/your_patch.patch

# Verify the fix
cat -A hostapd/patches/your_patch.patch | tail -5
```

**Verify with hexdump:**

```bash
# Check that context lines start with 0x20 (space)
hexdump -C hostapd/patches/your_patch.patch | tail -10
```

Look for `20 09` (space, tab) at the start of context lines, NOT just `09` (tab only).

**Prevention:**

1. **Always create patches using `diff -u`** - don't manually edit
2. **If you must edit a patch file**, use `cat <<'EOF'` with heredoc to preserve exact spacing
3. **After any edits, verify format** with `cat -A` or `hexdump -C`
4. **Test the patch** with `patch --dry-run` before committing

**Fix procedure:**

```bash
# 1. Check the format
cat -A hostapd/patches/problematic.patch | tail -10

# 2. Identify lines missing leading space (they start with ^I instead of  ^I)

# 3. Fix each context line (replace N with line number)
sed -i 'Ns/^\t/ \t/' hostapd/patches/problematic.patch

# 4. If the line starts with other text (not tab), add space at start:
sed -i 'Ns/^/ /' hostapd/patches/problematic.patch

# 5. Verify the fix
cat -A hostapd/patches/problematic.patch | tail -10

# 6. Test the patch applies
cd hostapd && rm -rf hostapd-2.11 && tar -xzf hostapd-2.11.tar.gz
cd hostapd-2.11 && patch -p1 --dry-run < ../patches/problematic.patch
```

### Issue 7: Wrong hunk header line counts

**Symptom:**

Patch fails with "malformed patch" even after fixing context line spacing.

**Root cause:**

The hunk header `@@ -START,COUNT +START,COUNT @@` must accurately reflect the number of lines:

- First COUNT: number of lines in the original file (context + removed lines)
- Second COUNT: number of lines in the new file (context + added lines)

**Example:**
```diff
@@ -182,6 +182,26 @@
```

Means:

- Original: starting at line 182, includes 6 lines
- New: starting at line 182, includes 26 lines (6 original + 20 added)

**How to calculate:**

1. Count context lines before your changes
2. Count lines you're removing (-)
3. Count lines you're adding (+)
4. Count context lines after your changes

Original COUNT = context_before + removed + context_after  
New COUNT = context_before + added + context_after

**How to fix:**

```bash
# If your patch has wrong counts, manually calculate and fix:
sed -i '3s/@@ -182,6 +182,22 @@/@@ -182,6 +182,26 @@/' your_patch.patch
```

**Tool to verify:**

```bash
# Count patch components
awk '/^[^@+-]/ || /^ / {ctx++} /^\+[^+]/ {add++} /^-[^-]/ {rem++} END {
  print "Context:", ctx, "Removed:", rem, "Added:", add
  print "Original lines:", ctx + rem
  print "New lines:", ctx + add
}' your_patch.patch
```

### Issue 8: Patches fail due to line number shifts from earlier patches

**Symptom:**
```
patching file src/ap/ieee802_11_eht.c
Hunk #1 FAILED at 291.
```

A patch fails even though it looks correct, because earlier patches to the same file shifted all the line numbers.

**Root cause:**

When multiple patches modify the same file, each patch changes line numbers for subsequent patches. The hunk header `@@ -START,COUNT` must reflect the ACTUAL line numbers after all previous patches have been applied.

**Example Scenario:**

1. `hostapd_eht_mcs_nss.patch` adds 20 lines starting at line 182
2. `eht_operation_basic_mcs_nss.patch` tries to modify line 238
3. But after patch #1, the original line 238 is now at a different line number!

**How to fix**

The ONLY reliable way to fix this is to:

1. Apply all previous patches sequentially to a clean source
2. Find the actual line number where your change belongs
3. Recreate the patch with correct line numbers using `diff -u`

**Complete fix procedure:**

```bash
# 1. Start with clean source
cd hostapd
rm -rf hostapd-2.11
tar -xzf hostapd-2.11.tar.gz
cd hostapd-2.11

# 2. Apply ALL patches that come before your failing patch
for patch in \
    ../patches/profiler_version_string.patch \
    ../patches/hw_features_profiler.patch \
    ../patches/vht_advertise_4ss.patch \
    ../patches/add_mld_config_struct.patch \
    ../patches/add_mld_config_parsing.patch \
    ../patches/add_mld_caps_override.patch \
    ../patches/hostapd_eht_mac_caps.patch \
    ../patches/hostapd_eht_mcs_nss.patch
do
    patch -p1 < $patch || exit 1
done

# 3. Find the actual line number of the code you want to modify
grep -n "TODO: Fill in appropriate EHT-MCS max Nss information" src/ap/ieee802_11_eht.c
# Output: 274:	/* TODO: Fill in appropriate EHT-MCS max Nss information */

# 4. Create backup and make your changes
cp src/ap/ieee802_11_eht.c src/ap/ieee802_11_eht.c.orig

# 5. Edit the file manually (use your editor or Python script)
# For example, using Python:
cat > /tmp/apply_changes.py <<'PYEOF'
with open('src/ap/ieee802_11_eht.c', 'r') as f:
    lines = f.readlines()

# Make your changes at the correct line numbers
# ...your edit logic here...

with open('src/ap/ieee802_11_eht.c', 'w') as f:
    f.writelines(lines)
PYEOF
python3 /tmp/apply_changes.py

# 6. Generate the NEW patch with correct line numbers
diff -u src/ap/ieee802_11_eht.c.orig src/ap/ieee802_11_eht.c > ../../patches/your_patch_FIXED.patch

# 7. Fix the file paths in the patch header
sed -i '1s|^--- src/|--- a/src/|; 2s|^+++ src/|+++ b/src/|' ../../patches/your_patch_FIXED.patch

# 8. Test the patch
cd ..
rm -rf hostapd-2.11
tar -xzf hostapd-2.11.tar.gz
cd hostapd-2.11

# Apply all patches including your fixed one
for patch in ../patches/*.patch; do
    echo "Testing: $patch"
    patch -p1 --dry-run < $patch || {
        echo "FAILED: $patch"
        exit 1
    }
done

echo "All patches apply successfully!"
```

- **Don't guess line numbers** - Line shifts are unpredictable when patches add/remove different amounts
- **Don't manually adjust hunk headers** - You'll likely get it wrong
- **Always use `diff -u`** - It calculates correct line numbers and counts automatically
- **Test the entire patch sequence** - Ensure all patches apply in order

**Quick check for line number:**

```bash
# After applying previous patches, find where your code is:
grep -n "your search text" src/ap/ieee802_11_eht.c

# The first number is the line you need in your hunk header
```

1. **Minimize multi-file patching** - If possible, put related changes in one patch
2. **Order patches carefully** - Group patches by file to minimize line shifting
3. **Document patch dependencies** - Note in comments which patches must come before others
4. **Use version control** - Track patches in git so you can regenerate them when needed

