# TODO

1. Pixel 8 does not send 802.11be capability to --fakeap mode

2. Pixel 8 does send 802.11be capability to AP mode (new default), but does not send MLE.

3. In --fakeap mode this appeared. WARNING] profiler.status: Failed to write /var/run/wlanpi-profiler.info: [Errno 2] No such file or directory: '/var/run/wlanpi-profiler.info.tmp' -> '/var/run/wlanpi-profiler.info'. And then later We had this:

* Reported client capabilities are dependent on available features at the time of client association.
** Reported channels do not factor local regulatory domain. Detected channel sets are assumed contiguous.
2026-01-26 00:29:19,561 [WARNING] profiler.status: Failed to write /var/run/wlanpi-profiler.info: [Errno 2] No such file or directory: '/var/run/wlanpi-profiler.info.tmp' -> '/var/run/wlanpi-profiler.info'
2026-01-26 00:30:00,053 [INFO] fakeap.py: Sniffer shutting down
2026-01-26 00:30:00,128 [WARNING] fakeap.py: beacon(): network is down or no such device (wlan0profiler) ... exiting ...
2026-01-26 00:30:00,154 [ERROR] start: Process TxBeacons-1 exited with code 14
2026-01-26 00:30:00,155 [ERROR] start: To investigate:
2026-01-26 00:30:00,155 [ERROR] start:   - Enable debug: Add 'debug: True' to /etc/wlanpi-profiler/config.ini [GENERAL] section
2026-01-26 00:30:00,303 [ERROR] start: Process profiler was killed (SIGKILL)
2026-01-26 00:30:00,304 [ERROR] start: To investigate:
2026-01-26 00:30:00,304 [ERROR] start:   - Enable debug: Add 'debug: True' to /etc/wlanpi-profiler/config.ini [GENERAL] section

4. We should capture the beacon used during profiling and add it to the pcap output and schema output. This is easy in --fakeap mode because we control the beacon. In hostapd mode (AP mode), we need to figure out how to do this. Monitor mode capture from another VIF does not work on iwlwifi / BE200. Maybe grep the hostapd logs? Might require always running hostapd in debug mode.
