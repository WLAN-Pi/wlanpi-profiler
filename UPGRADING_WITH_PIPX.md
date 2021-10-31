# Updating profiler2 via pipx on NEO{1,2} running WLAN Pi OS v2

If you would like to upgrade the shipped version of `profiler2` with WLAN Pi OS v2, please follow these instructions. Please note that these instructions do not work unless `profiler2` was installed via `pipx` either during the WLAN Pi image creation or you manually installed it that way.

## Prerequisites:

* Profiler is installed on your WLAN Pi via pipx
* WLAN Pi must have Internet access (GitHub specifically)
* You will need SSH/terminal access to the WLAN Pi

### Step 1. Update pipx

Command:

```
sudo python3 -m pip install -U pipx
```

### Step 2. Uninstall profiler2

In preparation for Debian packaging, the GitHub repo name for profiler was changed from `profiler2` to `wlanpi-profiler`.

This means `profiler2` must be first uninstalled before upgrading.

You will need to launch root shell and use the `-p` option to preserve the environment variables which tie `pipx` to `/opt/wlanpi/pipx`. The `-p` option prevents `su` from resetting `$PATH`.

Commands:

```
sudo su -p
pipx list
pipx uninstall profiler2
```

Expected Result:

```
wlanpi@wlanpi:~$ sudo su -p
root@wlanpi:/home/wlanpi# pipx uninstall profiler2
uninstalled profiler2! ✨ 🌟 ✨
```

### Step 3. Install latest version of wlanpi-profiler from the `main` branch.

Commands:

```
sudo su -p
pipx list
pipx install git+https://github.com/WLAN-Pi/wlanpi-profiler.git@main#egg=profiler
```

#### Validation:

You should see something like this in the output:

```
wlanpi@wlanpi:/$ pipx list
venvs are in /opt/wlanpi/pipx/venvs
apps are exposed on your $PATH at /opt/wlanpi/pipx/bin
   package profiler 1.0.7, Python 3.7.3
    - profiler
```

### Step 4. Migrate config file to new location:

Command:

```
sudo mv /etc/profiler2 /etc/wlanpi-profiler
```

## Appendix

### Future Upgrades for `wlanpi-profiler`

Once you've uninstalled `profiler2` and installed `wlanpi-profiler`, future upgrades can be done with `pipx upgrade profiler` like so: 

```
wlanpi@wlanpi:~$ sudo su -p
root@wlanpi:/home/wlanpi# pipx upgrade profiler
profiler is already at latest version 1.0.7 (location: /opt/wlanpi/pipx/venvs/profiler)
```

If you were to follow the previous `pipx install` instructions in attempt to upgrade `wlanpi-profiler`, you may see an error like this:

```
wlanpi@wlanpi:~$ sudo su -p
root@wlanpi:/home/wlanpi# pipx install git+https://github.com/WLAN-Pi/wlanpi-profiler.git@main#egg=profiler
'profiler' already seems to be installed. Not modifying existing installation in '/opt/wlanpi/pipx/venvs/profiler'. Pass '--force' to force installation.
```

### Install a specific version of wlanpi-profiler

You can specify the branch or tag like when installing via pipx. You can find the [tags here](https://github.com/WLAN-Pi/wlanpi-profiler/tags).

Here is an example for how we might install the v1.0.7rc2 tag:

```
sudo su -p
pipx install git+https://github.com/WLAN-Pi/wlanpi-profiler.git@v1.0.7rc2#egg=profiler
```
