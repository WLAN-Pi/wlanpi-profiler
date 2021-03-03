# Debian Packaging Instructions for Profiler

We're using spotify's dh-virtualenv to provide debian packaging and deployment of our Python code inside a virtualenv.

dh-virtualenv is like a wrapper or extension around existing debian tooling.

You can find the official page [here](https://github.com/spotify/dh-virtualenv).

Our goal is to use dh-virtualenv for packaging, PATH links, systemd service installation, and deployment virtualization.

## Getting Started

On your _build host_, install the build tools (these are only needed on your build host):

```
sudo apt-get install build-essential debhelper devscripts equivs python3-pip python3-all python3-dev python3-setuptools dh-virtualenv
```

Install Python depends:

```
python3 -m pip install mock
```

This appears to be required, otherwise the tooling will fail when tries to evaluate whether it needs to run tests or not.

## Build our project

From the root directory of this repository run `dpkg-buildpackage -us -uc -b`. 

If you are found favorable by the packaging gods, you should see some output files at `../profiler2` like this:

```
josh@DESKTOP-KU8SJRV:[~/profiler2]: ls ../ | grep wlanpi-
wlanpi-profiler_0.1-1_amd64.buildinfo
wlanpi-profiler_0.1-1_amd64.changes
wlanpi-profiler_0.1-1_amd64.deb
```

## APPENDIX

### Installing dh-virtualenv

Some OS repositories have packages already. 

```
sudo apt install dh-virtualenv
```

If not available, you can build it from source:

```
cd ~

# Install needed packages
sudo apt-get install devscripts python-virtualenv python-sphinx \
                     python-sphinx-rtd-theme git equivs
# Clone git repository
git clone https://github.com/spotify/dh-virtualenv.git
# Change into working directory
cd dh-virtualenv
# This will install build dependencies
sudo mk-build-deps -ri
# Build the *dh-virtualenv* package
dpkg-buildpackage -us -uc -b

# And finally, install it (you might have to solve some
# dependencies when doing this)
sudo dpkg -i ../dh-virtualenv_<version>.deb
```