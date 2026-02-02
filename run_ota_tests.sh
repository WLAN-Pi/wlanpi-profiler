#!/bin/bash
# Wrapper script to run OTA tests with sudo while preserving SSH access

# Run pytest as current user but with sudo for scapy raw socket access
# by using sudo's capability to setcap on python or running pytest through sudo -E

exec sudo -E \
  PATH="$PATH" \
  HOME="$HOME" \
  SSH_AUTH_SOCK="$SSH_AUTH_SOCK" \
  PROFILER_OTA_TESTS=1 \
  PROFILER_OTA_INTERFACE=wlu1u3 \
  PROFILER_REMOTE_HOST=wlanpi@198.18.42.1 \
  PROFILER_REMOTE_CHANNEL=36 \
  python3 -m pytest tests/test_ota_beacons.py "$@"
