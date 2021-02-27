# profiler packaging with dh-virtualenv

Exploratory use of dh-virtualenv for packaging, links, and services.

## Getting Started

Follow the [Getting Started](https://dh-virtualenv.readthedocs.io/en/latest/tutorial.html) from dh-virtualenv docs to setup your build host.

On your _build host_, install the build tools:

```
sudo apt-get install build-essential debhelper devscripts equivs
```

## Install dh-virtualenv

Some OS repositories have packages already. 

```
sudo apt install dh-virtualenv
```

If not available, build it:

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

## install mock

```
python3 -m pip install mock
```

## build our project

From the root directory of this repository run `dpkg-buildpackage -us -uc -b`. 

If all is well, you should see the `deb` file at `../profiler2`:

```
josh@DESKTOP-KU8SJRV:[~/profiler2]: ls ../ | grep wlanpi-
wlanpi-profiler_0.1-1_amd64.buildinfo
wlanpi-profiler_0.1-1_amd64.changes
wlanpi-profiler_0.1-1_amd64.deb
```

