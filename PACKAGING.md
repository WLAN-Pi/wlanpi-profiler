# Debian Packaging Instructions for Profiler

We're using spotify's dh-virtualenv to provide debian packaging and deployment of our Python code inside a virtualenv.

dh-virtualenv is essentially a wrapper or extension around existing debian tooling.

You can find the official page [here](https://github.com/spotify/dh-virtualenv).

Our goal is to use dh-virtualenv for packaging, symlinks, configuration files, systemd service installation, and virtualization at deployment.

## Getting Started

On your _build host_, install the build tools (these are only needed on your build host):

```
sudo apt-get install build-essential debhelper devscripts equivs python3-pip python3-all python3-dev python3-setuptools dh-virtualenv
```

Install Python depends:

```
python3 -m pip install mock
```

This is required, otherwise the tooling will fail when tries to evaluate which tests to run.

## Building our project

From the root directory of this repository run:

```
dpkg-buildpackage -us -uc -b
```

If you are found favorable by the packaging gods, you should see some output files at `../profiler` like this:

```
wlanpi@rbpi4b-8gb:[~/dev/profiler]: ls ../ | grep wlanpi-p
wlanpi-profiler_1.0.6_arm64.buildinfo
wlanpi-profiler_1.0.6_arm64.changes
wlanpi-profiler_1.0.6_arm64.deb
```

## Installing our deb with apt example

```
wlanpi@rbpi4b-8gb:[~/dev]: sudo apt install ~/dev/wlanpi-profiler_1.0.6_arm64.deb
Reading package lists... Done
Building dependency tree       
Reading state information... Done
Note, selecting 'wlanpi-profiler' instead of '/home/wlanpi/dev/wlanpi-profiler_1.0.6_arm64.deb'
The following NEW packages will be installed:
  wlanpi-profiler
0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Need to get 0 B/11.2 MB of archives.
After this operation, 40.0 MB of additional disk space will be used.
Get:1 /home/wlanpi/dev/wlanpi-profiler_1.0.6_arm64.deb wlanpi-profiler arm64 1.0.6 [11.2 MB]
Selecting previously unselected package wlanpi-profiler.
(Reading database ... 73199 files and directories currently installed.)
Preparing to unpack .../wlanpi-profiler_1.0.6_arm64.deb ...
Unpacking wlanpi-profiler (1.0.6) ...
Setting up wlanpi-profiler (1.0.6) ...
wlanpi-profiler.service is a disabled or a static unit, not starting it.
```

## sudo apt remove vs sudo apt purge

If we remove our package, it will leave behind the config file in /etc.

```
wlanpi@rbpi4b-8gb:[~/dev]: sudo apt remove wlanpi-profiler
[sudo] password for wlanpi: 
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following packages will be REMOVED:
  wlanpi-profiler
0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.
After this operation, 40.0 MB disk space will be freed.
Do you want to continue? [Y/n] y
(Reading database ... 76016 files and directories currently installed.)
Removing wlanpi-profiler (1.0.6) ...
wlanpi@rbpi4b-8gb:[~/dev]: cat /etc/wlanpi-profiler/config.ini 
#              ___ _ _                        ___ _     
#  ___ ___ ___|  _|_| |___ ___    ___ ___ ___|  _|_|___ 
# | . |  _| . |  _| | | -_|  _|  |  _| . |   |  _| | . |
# |  _|_| |___|_| |_|_|___|_|    |___|___|_|_|_| |_|_  |
# |_|                                              |___|
# 
```

If we don't want that, we need to purge it.

```
wlanpi@rbpi4b-8gb:[~/dev]: sudo apt purge wlanpi-profiler
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following packages will be REMOVED:
  wlanpi-profiler*
0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.
After this operation, 0 B of additional disk space will be used.
Do you want to continue? [Y/n] y
(Reading database ... 73201 files and directories currently installed.)
Purging configuration files for wlanpi-profiler (1.0.6) ...
```
## APPENDIX

### Build dependencies

If you don't want to satisfy build dependencies:

```
dpkg-buildpackage -us -uc -b -d
```
### Debian Packaging Breakdown

#### changelog

Contains changelog information and sets the version of the package

#### control

provides dependencies, package name, and other package meta data.

#### compat

sets compatibility level for debhelper

#### rules

this is the build recipe for make

#### wlanpi-profiler.install

this handles placing our config file in /etc
#### wlanpi-profiler.links

handles symlinks

#### wlanpi-profiler.postinst.debhelper

`dh-virtualenv` has an autoscript which handles this for us.

#### wlanpi-profiler.postrm.debhelper

`dh-virtualenv` has an autoscript which handles this for us.
#### wlanpi-profiler.service

`dh` automatically picks up and installs this systemd service

#### wlanpi-profiler.triggers

tells dpkg what packages we're interested in

### Installing dh-virtualenv

Some OS repositories have packages already. 

```
sudo apt install dh-virtualenv
```

If not available, you can build it from source:

```
cd ~

# Install needed packages
sudo apt-get install devscripts python3-virtualenv python3-sphinx \
                     python3-sphinx-rtd-theme git equivs
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