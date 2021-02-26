# profiler packaging with dh-virtualenv

Exploratory use of dh-virtualenv for packaging, links, and services.

Follow the [Getting Started](https://dh-virtualenv.readthedocs.io/en/latest/tutorial.html) from dh-virtualenv docs to setup your build host.

From the root directory of this repository run `dpkg-buildpackage -us -uc -b`. 

If all is well, you should see the a `deb` file at `../profiler2`:

```
josh@DESKTOP-KU8SJRV:[~/profiler2]: ls ../ | grep wlanpi-
wlanpi-profiler_0.1-1_amd64.buildinfo
wlanpi-profiler_0.1-1_amd64.changes
wlanpi-profiler_0.1-1_amd64.deb
```

