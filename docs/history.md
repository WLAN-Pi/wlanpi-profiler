Release x.x.x:

- Dependency on fork of `sheriffsparks/scapy-fakeap` removed
- Project is now packaged instead of a single script file
- Enable UTF-8 support for SSID broadcasting because emoji
- BPF filters applied sniff() to address sniff code perf issues with scapy processing beacons
- Leverage multiprocessing package to divide beacon, sniff, and profiler code between different processes  
- Obsolete `iwconfig` and `ipconfig` commands replaced with `iw` and `ip` equivalents for preparing the interface
- `manuf` package appears to be abandoned in Py3. replacing with manuf-ng https://github.com/daniel-leicht/manuf-ng
    + update seems to be the same with `sudo manuf --update`
- Tested on Python 3.7
- Add `--no11ax` switch to disable Tx of a HE information elements
- Enhanced debugging
- Continue use of arg parsing with standard library method for dealing with args