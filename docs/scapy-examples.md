### Reading in a HE frame to Analyze

```
>>> from scapy.all import rdpcap
>>> cap=rdpcap("mobile-he-beacon-1.pcap")
>>> cap
<mobile-he-beacon-1.pcap: TCP:0 UDP:0 ICMP:0 Other:1>
>>> for f in cap:
...     f.show()
...
###[ RadioTap dummy ]###
...
###[ 802.11 ]###
...
###[ 802.11 Beacon ]###
...
###[ 802.11 Information Element ]###
...

cap[0].summary
<bound method Packet.summary of <RadioTap  version=0 pad=0 len=25 present=TSFT+Flags+Rate+Channel+dBm_AntSignal+dBm_AntNoise+Antenna mac_timestamp=6997804 Flags=ShortPreamble+FCS Rate=12 ChannelFrequency=5200 ChannelFlags=OFDM+5GHz dBm_AntSignal=-73dBm dBm_AntNoise=-98dBm Antenna=1 notdecoded='' |<Dot11FCS  subtype=8 type=Management proto=0 FCfield= ID=0 addr1=ff:ff:ff:ff:ff:ff addr2=90:4c:81:76:1a:51 addr3=90:4c:81:76:1a:51 SC=57584 fcs=0x3885723b |<Dot11Beacon  timestamp=575118131735 beacon_interval=100 cap=res8+res12+ESS+privacy |<Dot11Elt  ID=SSID len=10 info='cmp-mobile' |<Dot11EltRates  ID=1 len=8 rates=[0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c] |<Dot11Elt  ID=DSset len=1 info='(' |<Dot11Elt  ID=TIM len=4 info='\x00\x01\x00\x00' |<Dot11EltCountry  ID=7 len=16 country_string='USI' descriptors=[<Dot11EltCountryConstraintTriplet  first_channel_number=36 num_channels=4 mtp=36 |>, <Dot11EltCountryConstraintTriplet  first_channel_number=52 num_channels=4 mtp=30 |>, <Dot11EltCountryConstraintTriplet  first_channel_number=100 num_channels=12 mtp=30 |>, <Dot11EltCountryConstraintTriplet  first_channel_number=149 num_channels=5 mtp=36 |>] pad=0 |<Dot11Elt  ID=32 len=1 info='\x00' |<Dot11Elt  ID=40 len=6 info='\x08\xc8\x1e\x00\x14\x00' |<Dot11Elt  ID=35 len=2 info='\x13\x00' |<Dot11EltRSN  ID=48 len=24 version=1 group_cipher_suite=<RSNCipherSuite  oui=0xfac cipher=CCMP |> nb_pairwise_cipher_suites=1 pairwise_cipher_suites=[<RSNCipherSuite  oui=0xfac cipher=CCMP |>] nb_akm_suites=2 akm_suites=[<AKMSuite  oui=0xfac suite=IEEE 802.1X / PMKSA caching |>, <AKMSuite  oui=0xfac suite=3 |>] mfp_capable=0 mfp_required=0 gtksa_replay_counter=2 ptksa_replay_counter=2 no_pairwise=0 pre_auth=0 reserved=0 |<Dot11Elt  ID=11 len=5 info='\x01\x00\x17\xbfr' |<Dot11Elt  ID=51 len=9 info='\x0c$(,0\x95\x99\x9d\xa1' |<Dot11Elt  ID=67 len=6 info='\x00\x0c\x11\xf9\x11\xf9' |<Dot11Elt  ID=70 len=5 info='s@\x01\x00\x01' |<Dot11Elt  ID=54 len=3 info='\x01\x00\x00' |<Dot11Elt  ID=HTCapabilities len=26 info='\xad\x01\x17\xfe\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |<Dot11Elt  ID=HTinfo len=22 info='(\x00\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |<Dot11Elt  ID=ExtendendCapatibilities len=8 info='\x04\x00\x08\x00\x00\x00\x00@' |<Dot11Elt  ID=VHTCapabilities len=12 info='\x90\x01\x80\x03\xaa\xff\x00\x00\xaa\xff\x00 ' |<Dot11Elt  ID=192 len=5 info='\x00\x00\x00\x00\x00' |<Dot11Elt  ID=195 len=3 info='\x01??' |<Dot11Elt  ID=255 len=32 info='#\x01\x00\x00\x12\x00\x10\x00 \x0e@l[\x83\x18\x00\x0c\x00\xaa\xff\xaa\xff\x1b\x1c\xc7q\x1c\xc7q\x1c\xc7q' |<Dot11Elt  ID=255 len=7 info='$\xf4?\x00\x00\xfc\xff' |<Dot11Elt  ID=255 len=14 info='&\x00\x00\xa4\xff \xa4\xff@C\xff`2\xff' |<Dot11EltVendorSpecific  ID=221 len=17 oui=0xb86 info='\x01\x03\x00pghmad02ap2' |<Dot11EltVendorSpecific  ID=221 len=24 oui=0x50f2 info="\x02\x01\x01\x80\x00\x03\xa4\x00\x00'\xa4\x00\x00BC^\x00r2/\x00" |<Dot11EltVendorSpecific  ID=221 len=7 oui=0xb86 info='\x01\x04\x08\x13' |>>>>>>>>>>
```