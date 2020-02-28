# RealTek vs MediaTek Performance

MediaTek adapters seem to perform better.

# Profiler Code lives in Userland

It would be much more efficient to not use scapy, which comes with much overhead, but complexity increases.

# Profiler Probe Responses are Retried

- what's happening? appears probe resp from profiler is not being ack'd by clients. or, if it is, scapy is not recognizing that it is being ack'd. 

- the # of retries also vary across drivers for example the Netgear A6210 sends more retries than the Comfast 912AC.

- one hypothesis is the client moves on to another channel during it's network discovery "scan", before the profiler gets it's probe resp in the air, so the client never sends an ACK because it moved on and never "heard" the probe response. [more here on scapy performance](https://stackoverflow.com/questions/11348328/low-performance-with-scapy#12115066).

- after some profiling, the script takes anywhere between 40 and 110 milliseconds to send a probe response. 

- this may impact discoverability of the profiler ssid depending on the client.