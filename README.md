# Distributed-Wifi-Capability-Collector(DWCC)
This project is designed to passively collect WIFI(802.11) management frames from inexpensive sensors distruted to see what features and specifications your WIFI clients support.

The plan is to collect pcaps then analyze them extracting the relevant data on the sensor.  Then sending it to a central database.  

## Supported collected info
The following specifications and features are collected and in the future we will include reports displaying the results of the collection.
* 80 Mhz channel support = wlan_mgt.vht.capabilities.short80
* 160 Mhz channel support = wlan_mgt.vht.capabilities.short160 
* 802.11W = wlan.fc.protected(this one needs more fact checking)
* MAC address of the client =  wlan.sa
* MAC address of the AP receiving the packet =  wlan.bssid
* frequency the client transmitted on =  radiotap.channel.freq
* BSS Transition(aka 802.11r aka FT) = wlan_mgt.extcap.b19 
*	Channel = wlan_radio.channel 
* wlan.fc.pwrmgt
* wlan_mgt.fixed.capabilities.radio_measurement 
* wlan_mgt.ht.mcsset.txmaxss 
* radiotap.channel.flags.ofdm 
* radiotap.channel.flags.5ghz
* radiotap.channel.flags.2ghz 
* wlan_mgt.fixed.capabilities.spec_man
* wlan_mgt.powercap.max 
* wlan_mgt.powercap.min 
* wlan_mgt.rsn.capabilities.mfpc 
* wlan_mgt.extcap.b31
* wlan_mgt.extcap.b32
* wlan_mgt.extcap.b46
* wlan_mgt.tag.number 
* Maximum MPDU Length = wlan_mgt.vht.capabilities.maxmpdulength 
* Supported Channel Width set = wlan_mgt.vht.capabilities.supportedchanwidthset
* Receive LDPC-encoded frames = wlan_mgt.vht.capabilities.rxldpc 
* Tansmission of STBC-coded frames = wlan_mgt.vht.capabilities.txstbc 
* Support for client to receive from ap that is doing beamforming = wlan_mgt.vht.capabilities.subeamformer (this one needs more fact checking)
* wlan_mgt.vht.capabilities.subeamformee (this one needs more fact checking)
* wlan_mgt.vht.capabilities.beamformerants
* wlan_mgt.vht.capabilities.soundingdimensions
* wlan_mgt.vht.capabilities.mubeamformer
* wlan_mgt.vht.capabilities.mubeamformee
* wlan_mgt.tag.oui

Great details about some of the above can be found on http://chimera.labs.oreilly.com/books/1234000001739/ch03.html#management_frames

## Hardware examples
__Example 1:__
* Wireless=Alfa AWUS051NH ($70)
* CPU=Raspberry Pi 3 ($39)
* You would still SD card, case,  and power supply
* Cost=~$150

__Example 2:__
* TBD 
