
# Upgrading profiler with pipx on NEO2 / WLAN Pi 2.0.1 

If you'd like to upgrade profiler on your existing NEO 2 WLAN Pi which is running WLAN Pi 2.0.1, please follow these instructions.

Challenges:

* The GitHub repo for profiler was changed from profiler2 to wlanpi-profiler in preparation for debian packaging. This means we need to uninstall profiler2 from pipx.
* PATH complications with pipx. We need to pass some env variables to sudo.

## Prerequisites:

* WLAN Pi must have Internet access (GitHub specifically)
* You will need SSH/terminal access to the WLAN Pi

## Step 1:

Command:

```
sudo python3 -m pip install -U pipx
```

## Step 2:

Command:

```
sudo PIPX_HOME=/opt/wlanpi/pipx PIPX_BIN_DIR=/opt/wlanpi/pipx/bin pipx uninstall profiler2
```

Expected Result:

```
wlanpi@wlanpi:~$ sudo PIPX_HOME=/opt/wlanpi/pipx PIPX_BIN_DIR=/opt/wlanpi/pipx/bin pipx uninstall profiler2
uninstalled profiler2! ✨ 🌟 ✨
```

## Step 3:

Command:

```
sudo PIPX_HOME=/opt/wlanpi/pipx PIPX_BIN_DIR=/opt/wlanpi/pipx/bin pipx install git+https://github.com/WLAN-Pi/wlanpi-profiler.git@main#egg=profiler
```

Expected Result:

```
wlanpi@wlanpi:~$ sudo PIPX_HOME=/opt/wlanpi/pipx PIPX_BIN_DIR=/opt/wlanpi/pipx/bin pipx install git+https://github.com/WLAN-Pi/wlanpi-profiler.git@main#egg=profiler
  installed package profiler 1.0.7, Python 3.7.3
  These apps are now globally available
    - profiler
⚠️  Note: '/root/.local/bin' is not on your PATH environment variable. These apps will not be globally accessible until your PATH is updated. Run `pipx ensurepath` to automatically add it, or manually modify your PATH in your shell's config file (i.e. ~/.bashrc).
done! ✨ 🌟 ✨
```

### Validation:

You should see something like this in the output:

```
wlanpi@wlanpi:/$ pipx list
venvs are in /opt/wlanpi/pipx/venvs
apps are exposed on your $PATH at /opt/wlanpi/pipx/bin
   package profiler 1.0.7, Python 3.7.3
    - profiler
```

If you see the following, something went wrong.

```
profiler (symlink missing or pointing to unexpected location)
```

## Step 4 (optional):

Migrate config file to new location.

Command:

```
sudo mkdir /etc/wlanpi-profiler
sudo cp /etc/profiler2/config.ini /etc/wlanpi-profiler/
```

## Step 5 (optional):

Fix permissions on pipx logs so that we can run `pipx list` without sudo and errors.

```
sudo chown -R wlanpi:wlanpi /opt/wlanpi/pipx/logs
```