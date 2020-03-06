Release x.x.x:

- Port of original profiler to Python 3.7 (🐍)
- Dependency on `sheriffsparks/scapy-fakeap` removed 
- Project is now packaged instead of a single script file (`pip install .`)
- Enable UTF-8 support for SSID broadcasting (because emoji 😀)
- BPF filters applied to scapy's `sniff()` in attempt to address perf issues with processing beacon overhead
- Leverage multiprocessing standard library package to separate beacon, sniffing, and profiler code onto different processes  
- Interface prepartion commands `iwconfig` and `ipconfig` replaced with `iw` and `ip` equivalents
- `manuf` package appears to be abandoned in Py3. replaced with manuf-ng https://github.com/daniel-leicht/manuf-ng
- Add `--oui_update` switch to trigger manuf.py to update the local OUI flat file from Internet
- Add `--no11ax` switch to disable Tx of a HE information elements
- Add `--crust` switch to add support for WLAN Pi v2.0 WebUI
- Add `--host_ssid` switch to use the WLAN Pi's hostname as the SSID
- Add `--logging` switch to increase print verbosity for debugging 
- Begin use of `pytest` and `tox` to standardize testing and linting
- Adopt a license, style guide, contributing guidelines, and code of conduct