# Interface Staging Note for Various Cards

## iwlwifi 

When we think about supporting iwlwifi cards like the Intel AX200 or AX210, we have to change our staging approach.

Simply putting an interface in monitor mode and setting the frequency is not sufficient.

With iwlwifi, there is a location-aware piece which controls whether a particular channel has `No IR` or `Disabled` flags.

If we perform a scan with the iwlwifi interface, this may remove the `No IR` or `Disabled` flags from said channel.

If `No IR` or `Disabled` is present, injection will not work, meaning profiler will not work.

This means for `iwlwifi`, we need to follow a particular sequence of events for interface staging. 

1. Kill wpa_supplicant
2. Set the interface in managed mode and perform a scan
3. Create a monitor subinterface
4. Bring up the monitor subinterface
5. Turn down the interface
6. Set the frequency for the monitor subinterface

The commands look something like this:

```
sudo wpa_cli -i wlan0 terminate
sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up
sudo iw wlan0 scan > /dev/null
sudo iw phy0 interface add mon0 type monitor flags none
sudo ip link set mon0 up
sudo ip link set wlan0 down
sudo iw mon0 set freq 5180 HT20
iwconfig  && sudo iw phy phy0 channels | grep -A 3 5180
```

## rtl88XXau

In my testing, USB cards such as the Comfast CF-912AC do not like the monitor interface. And injection does not work. I have also seen the host device crash on profiler exit and cleanup of the monitor interface (iw dev mon0 del).

This means we need to support multiple interface staging approaches depending on which driver is used.

The staging for rtl88XXau that works looks like this:

```
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw wlan0 set freq 5180 HT20
```