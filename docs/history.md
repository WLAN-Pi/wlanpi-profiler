Release x.x.x:

- No dependency on scapy-fakeap
- Tested on Python 3.7 and 3.8
- Project is a packaged instead of a single script file
- Use standard library for parsing and dealing with args
- Enable UTF-8 support for SSID broadcasting because emoji
- BPF filters applied sniff() to address sniff code perf issues with scapy processing beacons
- Load app configuration from YAML file `config.yml`
    - TODO: should this instead be from the std library instead? REVISIT
- Exploring Multi Processing to separate beacon, sniff, and analysis code - although unsure how to determine perf challenges are CPU bound or IO bound.
- Enhanced debugging
- Obsolete `iwconfig` and `ipconfig` commands replaced with `iw` and `ip` equivalents for preparing the interface