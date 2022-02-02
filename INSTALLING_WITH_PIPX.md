# Installing `wlanpi-profiler` using pipx

It is possible to install `profiler` outside of the WLAN Pi ecosystem on distributions such as Debian or Ubuntu using the `pipx` package manager.

Assumptions:

* `profiler` does not already exist on the host
* you are comfortable running `profiler` from the terminal on the host

The base requirements to install and use profiler include:

* Python 3.7+, pip, and pipx 
* root permissions on your OS
* a WLAN adapter capable of monitor mode + packet injection (profiler assumes adapter name is `wlan0` by default)

## Tradeoffs of this installation method

* manpage entry is not installed; `man wlanpi-profiler` does not work
* config.ini is not installed; `/etc/wlanpi-profiler/config.ini` does not exist
* systemd service unit is not installed; `sudo service wlanpi-profiler status` will not work

## Installing the dependencies (Debian package manager)

These are the instructions for first time installs.

1. Download updated package information from configured sources

```bash
sudo apt update
```

2. Install Python3 and pip

```bash
sudo apt install python3 python3-pip
```

3. Update pip, setuptools, and wheel to the latest versions

```bash
python3 -m pip install -U pip setuptools wheel
```

4. Install [Pipx from PyPI](https://pypi.org/project/pipx/) with pip

Note: it's important to use the `-p` argument to preserve the environment variables. The `-p` option prevents `su` from resetting `$PATH`.

```bash
sudo su -p
python3 -m pip install pipx
python3 -m pipx ensurepath
exit
```

5. Install `profiler` from source

```bash
sudo su -p
pipx install git+https://github.com/WLAN-Pi/wlanpi-profiler.git@main#egg=profiler
exit
```

Ok, validate that it's installed!

```bash
sudo su -p
which pipx
which profiler
profiler --version
```

You should see something like this:

```bash
# which pipx
/usr/local/bin/pipx
# which profiler
/root/.local/bin/profiler
# profiler --verison
1.0.13
```

## Running profiler

Usage:

```bash
$ sudo su -p
# profiler -h
```

Custom settings

```bash
$ sudo su -p
# profiler -i wlan1 -c 40 -s "My custom SSID"
```

Verbose/debug mode:

```bash
$ sudo su -p
# profiler --debug
```

## Upgrading profiler

1. Update pipx to the latest (optional)

```bash
sudo python3 -m pip install -U pipx
```

```
$ sudo su -p
# pipx upgrade profiler
profiler is already at latest version 1.0.13 location: /root/.local/pipx/venvs/profiler)
```

## Uninstalling profiler

```bash
$ sudo su -p
# pipx uninstall profiler
uninstalled profiler! ✨ 🌟 ✨
```

## Installing a specific version of profiler

You can specify the branch or tag like when installing via pipx. You can find the [tags here](https://github.com/WLAN-Pi/wlanpi-profiler/tags).

Here is an example for how we might install the v1.0.13 tag:

```bash
$ sudo su -p
# pipx install git+https://github.com/WLAN-Pi/wlanpi-profiler.git@v1.0.13#egg=profiler
```

Please let us know if there are any mistakes in these instructions. Thanks!
