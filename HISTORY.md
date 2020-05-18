Relase 0.0.1.dev2:

- Remove pymongo dependency and related code

Release 0.0.1.dev1:

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
- Add `--crust` switch to add support for WLAN Pi v2.0 WebUI
- Add `--host_ssid` switch to use the WLAN Pi's hostname as the SSID
- Add `--logging` switch to increase print verbosity for debugging
- Begin use of `pytest` and `tox` to standardize testing and linting
- Adopt a license, style guide, contributing guidelines, and code of conduct