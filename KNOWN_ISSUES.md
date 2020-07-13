# RealTek vs MediaTek Driver Performance

MediaTek adapters seem to perform better.

# Beacon timestamp values are wrong

Something (scapy?) between our Python code and the on-air beacon is messing with the timestamp value. 

# Profiler retries Probe Response frames

- problem: profiler2 does not respond quick enough before the client moves onto another channel during discovery.

- hypothesis: during a clients Wi-Fi discovery, the client sends a probe request on a particular channel and then listens for a very short period of time. after some waiting period, it moves to another channel. i think the client moves to another channel before the profiler parses the probe req, builds a probe resp frame, and then puts that probe resp frame on the air. this would mean the client never sends an ACK, because the client has moved on to scan another channel, and never heard the probe resp because it is no longer listening on the same channel. 

- script performance: after some script profiling analysis, profiler2 takes anywhere between 40 and 110 milliseconds to send a probe response. i believe this is due to profiler2 code living in userspace + scapy overhead. [more here on scapy performance](https://stackoverflow.com/questions/11348328/low-performance-with-scapy#12115066). 

- observation 1: looking through single channel wireshark captures of this behavior, it appears often the probe resp is never ACK'd by the client.

- observation 2: i've observed one way you can get a client to ACK a profiler probe resp, is to first associate the client to an AP. and second start the profiler on the same channel as the AP.  the clients discovery scan you may see the client ACK the profiler's probe resp. 

![](https://github.com/joshschmelzle/profiler2/blob/main/docs/images/2020.02.28t2045-probe-resp-capture.PNG)

- observation 3: the # of retries also vary across drivers for example the Netgear A6210 (MediaTek) sends more retries than the Comfast 912AC (RealTek).

- warning: depending on the client, this may impact discoverability of the profiler ssid.
