Release 1.0.0-alpha2

- add --yes flag to support automatic yes to --clean y/n prompt

Release 1.0.0-alpha1

- create and change default branch from master to main
- fix handling of `--no11r` and `--no11ax` modes from either CLI args or config file
- menu mode tweaks and is now enabled by default
- minor changes to flat file output such as including the capture channel
- `manuf` is no longer abandoned: replaced it's fork `manuf-ng` and updated `manuf` to working version

Release 0.1.dev6:

- Fix a helper function returning wrong IP of SSH session
- Place all flat files for a particular client in its subfolder
- Lock down scapy to version 2.4.3
- Change 5.0 GHz band marking to 5.8GHz

Release 0.1.dev5:

- Fix bug that prevents profiler.service starting from cockpit
- Only run on Python>=3.7 

Release 0.1.dev4:

- Specify required scapy version in install_requires and requirements

Release 0.1.dev3:

- Console_scripts entry point changed from profiler2 to profiler
- Minor bug fixes
- Fix permissions check

Release 0.1.dev2:

- 2.4 or 5 GHz markings are now appended to filenames for flat files
- Minor refactors and bug fixes
- Allow user to run w/o valid WLAN interface for pcap analysis mode (say running from WSL)
- Remove pymongo dependency and related code

Release 0.1.dev1:

- Port of original [profiler](https://github.com/WLAN-Pi/profiler) to Python 3.7 (:snake:)
- Dependency on `sheriffsparks/scapy-fakeap` removed
- Project is now packaged instead of a single script file (e.g. `python3 -m pip install .` from repo root dir works)
- Enable UTF-8 support for SSID broadcasting (because emoji :grinning:)
- BPF filters applied to scapy's `sniff()` function in attempt to address perf issues with processing beacon overhead
- Leverage multiprocessing stdlib package to separate beacon, sniffing, and profiler code onto different processes
- Interface prepartion commands `iwconfig` and `ipconfig` replaced with `iw` and `ip` equivalents
- `manuf` package appears to be abandoned in Py3. replaced with [manuf-ng](https://github.com/daniel-leicht/manuf-ng)
- Add `--oui_update` switch to trigger manuf.py to update the local OUI flat file from Internet
- Add `--no11ax` switch to disable Tx of 802.11ax HE information elements
- Add `--host_ssid` switch to use the WLAN Pi's hostname as the SSID
- Add `--logging` switch to increase print verbosity for debugging
- Begin use of `pytest` and `tox` to standardize testing and linting
- Adopt a license, style guide, contributing guidelines, and code of conduct
