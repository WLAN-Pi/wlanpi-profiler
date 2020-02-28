# THIS IS A WORK IN PROGRESS AND NOT READY FOR USE OUTSIDE OF DEVELOPMENT

# profiler2

begining of a port and optimization of the WLAN Pi profiler from py2 to py3 and removing an external FakeAP dependency.

## installation

pre-reqs:

- minimum `Python 3.6` installed ([instructions for building from source](https://gist.github.com/joshschmelzle/e84d3060cc987d3ccb3a141cab9ffbb1))
- `airmon-ng` installed

install: 

```
# get code
git clone <repo>
cd <repo>

# to install
sudo python3 -m pip install .

# or just to run w/o installing
sudo python3 -m profiler2 <params>

# run w/o installing examples
sudo python3.7 -m profiler2 
sudo python3.7 -m profiler2 -c 40 -s "WLAN Pi Dev" -logging debug
```

## how to prep your interface and set the channel manually:

```
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw wlan0 set channel 100

# verify commands:
sudo iw dev
sudo iw wlan0 info
```

# appendix/misc/TODO: delete/move

## canvas_dump fun

want to export a dissection of a beacon to pdf? install pyx (and dependency texlive) to make use scapy's .canvas_dump to pdf.

```
sudo apt install texlive
sudo python3.7 -m pip install pyx
```

## [testing nic for injection](https://www.aircrack-ng.org/~~V/doku.php?id=injection_test)

This is a basic test to determine if you card successfully supports injection.

```
sudo aireplay-ng -9 wlan0
```

## check kernel for CONFIG_PACKET

[Is socket support?](https://unix.stackexchange.com/questions/72519/how-do-i-check-if-i-have-packet-socket-support-enabled-in-my-distros-kernel)

```
grep -x 'CONFIG_PACKET=[ym]' "/boot/config-$(uname -r)"
```

## caveats 

Known bugs in scapy (collected 2019/12/03 from https://scapy.net/):

- may miss packets under heavy load

## known/might fix/might not

- client does not ack probe responses from scapy which may or may not be an issue.

## find usb nic info like driver versions

```
usb-devices | less

lsmod
lsmod | grep 80211
cfg80211              294912  1 88XXau

sudo modinfo 88XXau | grep version
version:        v5.2.20.2_28373.20180619
```
