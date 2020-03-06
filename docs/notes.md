
# notes (mostly appendix/misc)

## scapy canvas_dump fun

want to export a dissection of a beacon to pdf? install pyx (and dependency texlive) to make use scapy's .canvas_dump to pdf.

```
sudo apt install texlive
sudo python3.7 -m pip install pyx
```

## [testing a NIC for injection](https://www.aircrack-ng.org/~~V/doku.php?id=injection_test)

This is a basic test to determine if you card successfully supports injection.

```
sudo aireplay-ng -9 wlan0
```

## check kernel for CONFIG_PACKET

[Is socket support?](https://unix.stackexchange.com/questions/72519/how-do-i-check-if-i-have-packet-socket-support-enabled-in-my-distros-kernel)

```
grep -x 'CONFIG_PACKET=[ym]' "/boot/config-$(uname -r)"
```

## ways to discover info about a USB NIC, like driver versions

```
usb-devices | less

lsmod
lsmod | grep 80211
cfg80211              294912  1 88XXau

sudo modinfo 88XXau | grep version
version:        v5.2.20.2_28373.20180619
```
