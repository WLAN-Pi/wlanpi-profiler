# RealTek vs MediaTek Driver Performance

MediaTek adapters seem to perform better.

# Beacon timestamp values are wrong

Something between our code and the on air beacon is messing with the timestamp value. 

# Profiler Probe Response Retries

- what's happening? the profiler does not respond before the client moves onto another channel.

- my hypothesis is that during network discovery, the client listens/sends a probe request for a short period of time, and then moves on to another channel before the profiler parses the probe req, builds a probe resp frame, and then puts that probe resp frame on the air. so the client does not send an ACK, because it has moved on to scan another channel and never heard the probe resp. 

- looking through single channel wireshark captures, it appears often the probe resp is never ACK'd by the client. one way you can get a client to ACK a profiler probe resp, is to associate the client to an AP on the same channel as the profiler, and then start a capture of the discovery scan by the client.

![](docs/images/2020.02.28t2045-probe-resp-capture.png)

- the # of retries also vary across drivers for example the Netgear A6210 (MediaTek) sends more retries than the Comfast 912AC (RealTek).

- after some profiling, the script takes anywhere between 40 and 110 milliseconds to send a probe response. i'm guessing this is due to this code living in userspace + scapy overhead [more here on scapy performance](https://stackoverflow.com/questions/11348328/low-performance-with-scapy#12115066).

- this may impact discoverability of the profiler ssid depending on the client.