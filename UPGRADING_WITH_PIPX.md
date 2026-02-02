# Updating profiler2 via pipx on NEO{1,2} running WLAN Pi OS v2

NOTE: THIS IS AN MAINTAINED DOCUMENT PRESERVED FOR HISTORY

If you would like to upgrade the shipped version of `profiler2` with WLAN Pi OS v2, please follow these instructions. Please note that these instructions do not work unless `profiler2` was installed via `pipx` either during the WLAN Pi image creation or you manually installed it that way.

## Prerequisites

* Profiler is installed on your WLAN Pi via pipx
* WLAN Pi must have Internet access (GitHub specifically)
* You will need SSH/terminal access to the WLAN Pi

## Why this process

* Pipx needs to be upgraded otherwise you will get errors following this process.
* When profiler was shipped with the NEO2 platform, the repository it was downloaded from was profiler2, but it has since been renamed.
* This means we have to uninstall `profiler2` via pipx, and then reinstall `wlanpi-profiler` via pipx.

## We're moving away from pipx

In our future releases, we're packaging profiler into an installable Debian package (`.deb`).   

So, we're moving away from using pipx to install and upgrade profiler, but you can still use this method for 1) upgrading profiler on legacy NEO2 platforms via pipx or 2) installing profiler via pipx on other Linux distributions.

Otherwise, on WLAN Pi OS v3.0.0+, you'll want to use `sudo apt install wlanpi-profiler` or `sudo apt upgrade wlanpi-profiler` to install or upgrade the latest version of profiler.

Let's get back to the pipx process:

### Step 1. Update pipx

Command:

```bash
sudo python3 -m pip install -U pipx
```

### Step 2. Uninstall profiler2

In preparation for 1) packaging applications into Debian apps for WLAN Pi OS v3 and 2) having a unique name (profiler is not unique to us), both the application name and GitHub repo name was changed from `profiler2` to `wlanpi-profiler`. 

What this means is `profiler2` must be first uninstalled before upgrading. Sorry about that!

You will need to launch root shell and use the `-p` option to preserve the environment variables which tie `pipx` to `/opt/wlanpi/pipx`. The `-p` option prevents `su` from resetting `$PATH`.

Commands:

```bash
sudo su -p
pipx list
pipx uninstall profiler2
```

Expected Result:

```bash
wlanpi@wlanpi:~$ sudo su -p
root@wlanpi:/home/wlanpi# pipx uninstall profiler2
uninstalled profiler2! ✨ 🌟 ✨
```

Ok, we've upgraded pipx and uninstalled profiler2 which has linkrot to an old repository. Great!

### Step 3. Install latest version of wlanpi-profiler from the `main` branch.

Commands:

```bash
sudo su -p
pipx list
pipx install git+https://github.com/WLAN-Pi/wlanpi-profiler.git@main#egg=profiler
```

#### Validation:

You should see something like this in the output:

```bash
wlanpi@wlanpi:/$ pipx list
venvs are in /opt/wlanpi/pipx/venvs
apps are exposed on your $PATH at /opt/wlanpi/pipx/bin
   package profiler 1.0.14, Python 3.7.3
    - profiler
```

### Step 4. Migrate config file to new location:

Command:

```bash
sudo mv /etc/profiler2 /etc/wlanpi-profiler
```

Ok, you should be able to run profiler from the shell now.

Check it out:

```bash
$ which profiler
$ profiler -h
$ profiler --version
```

## Appendix

### Future Upgrades for `wlanpi-profiler`

Once you've uninstalled `profiler2` and installed `wlanpi-profiler`, future upgrades can be done with `pipx upgrade profiler` like so: 

```bash
wlanpi@wlanpi:~$ sudo su -p
root@wlanpi:/home/wlanpi# pipx upgrade profiler
profiler is already at latest version 1.0.14 (location: /opt/wlanpi/pipx/venvs/profiler)
```

If you were to follow the previous `pipx install` instructions in attempt to upgrade `wlanpi-profiler`, you may see an error like this:

```bash
wlanpi@wlanpi:~$ sudo su -p
root@wlanpi:/home/wlanpi# pipx install git+https://github.com/WLAN-Pi/wlanpi-profiler.git@main#egg=profiler
'profiler' already seems to be installed. Not modifying existing installation in '/opt/wlanpi/pipx/venvs/profiler'. Pass '--force' to force installation.
```

### Install a specific version of wlanpi-profiler

You can specify the branch or tag like when installing via pipx. You can find the [tags here](https://github.com/WLAN-Pi/wlanpi-profiler/tags).

Here is an example for how we might install the v1.0.14 tag:

```bash
sudo su -p
pipx install git+https://github.com/WLAN-Pi/wlanpi-profiler.git@v1.0.14#egg=profiler
```
