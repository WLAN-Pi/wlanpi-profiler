# How to use `iw` and `ip` to prep your WLAN NIC to Tx frames

The tools `iwconfig` and `ipconfig` that are commonly known and used are actually obsolete and have been replaced with modern tools like `iw` and `ip`.# How to use `iw` and `ip` to prep your WLAN NIC to Tx frames

The tools `iwconfig` and `ipconfig` that are commonly known and used are actually obsolete and have been replaced with modern tools like `iw` and `ip`.

`iw` was meant to replace `iwconfig`.

You can use `iw dev` to list devices.

### Step 1. 

Determine if card supports monitor mode using `iw`:

```buildoutcfg
iw phy phy0 info
```

### Step 2.

Admin down the interface:

```buildoutcfg
sudo ip link set wlan0 down
```

### Step 3.

Change interface from managed to monitor:

```buildoutcfg
sudo iw wlan0 set monitor none
```

### Step 4.

Bring up the interface:

```buildoutcfg
sudo ip link set wlan0 up
``` 

### Step 5.

Set the channel you want to capture or inject on:

```buildoutcfg
sudo iw dev wlan0 set channel 36 
```

# Scripts

```buildoutcfg
# wlan0 example

sudo ip link set wlan0 down
sudo iw wlan0 set monitor none
sudo ip link set wlan0 up

# setting channel example

sudo iw wlan0 set channel 36

# wlp4s0 example

sudo ip link set wlp4s0 down
sudo iw wlp4s0 set managed
sudo ip link set wlp4s0 up

# stopping problematic processes

airmon-ng check kill
systemctl stop NetworkManager
```

# Check NIC Info

```buildoutcfg
sudo iw dev
sudo iw wlan0 info
```