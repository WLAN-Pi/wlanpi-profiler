Releaes 1.0.7

- Allow read of pcap file when no WLAN NICs are present
- Allow reading and analysis of multiple association requests in a single pcap
- Make output to screen less noisy by default
- Add output to JSON flat file to support backend
- Fix listen only/passive mode (--noAP) which listens for any association request on a set channel
- Remove draft label from 802.11ax detection
- Add MCS detection for 802.11ac and 802.11ax
- Add 160 MHz support for 802.11ac and 802.11ax
- Add feature detection for 802.11ax TWT, Punctured Preamble, HE SU Beamformer, HE SU Beamformee, HE (ER) Extended Range, UORA (Uplink OFDMA Random Access), and BSR Control (Buffer Status Report)
- Basic Wi-Fi 6E client association pcap profiling
- Add Intel to client manufacturer detection heuristic
- Interface staging improvements
- Fix crash that happens when utf-8 decoding fails

Release 1.0.6

- Replace pipx packaging with debian packaging

Release 1.0.5

- Add support for deleting profiled files (.txt and .pcap) in addition to reports
- Improve test coverage

Release 1.0.4 

- Fix issue preventing a client from being profiled again in the same session when switching between Private MAC and Device MAC
- Fix problem with oui lookups sometimes failing
- Add Samsung to the client heuristics detection
- Add unit tests for client heuristics detection

Release 1.0.3

- Add heuristics to resolve the manufacturer when a client is using a randomized mac address
- Fix forged beacon interval

Release 1.0.2

- Add basic detection for randomized mac addresses

Release 1.0.1

- Bump scapy version from 2.4.3 to 2.4.4

Release 1.0.0-alpha3

- Improve test coverage
- Begin detecting and reporting on changed client capabilities
- App now looks for config.ini in /etc/profiler2/

Release 1.0.0-alpha2

- Add --yes arg to support automatic yes to --clean y/n prompt
- Refactors; bump tox version in requirements
- Remove menu mode code that is no longer used in WLAN Pi v2 builds
- Allow user to check help usage and version without root permissions
- Remove airmon-ng check kill from interface preparation when profiler is run
- Refactor and improve test coverage
- Fix error where argparse fails to allow profiler to run on channel 2
- Rename GH workflow

Release 1.0.0-alpha1

- Bump major to 1 because package is in production WLAN Pi image.
- Create and change default branch from master to main
- Fix handling of `--no11r` and `--no11ax` modes from either CLI args or config file
- Menu mode tweaks and is now enabled by default
- Minor changes to flat file output such as including the capture channel
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
