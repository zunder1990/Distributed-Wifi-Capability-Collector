80 Mhz channel support = wlan_mgt.vht.capabilities.short80 done
160 Mhz channel support = wlan_mgt.vht.capabilities.short160 done
802.11W = wlan.fc.protected(this one needs more fact checking)
MAC address of the client = wlan.sa
MAC address of the AP receiving the packet = wlan.bssid
frequency the client transmitted on = radiotap.channel.freq 
BSS Transition(aka 802.11r aka FT) = wlan_mgt.extcap.b19 done
Channel = wlan_radio.channel done
wlan.fc.pwrmgt
wlan_mgt.fixed.capabilities.radio_measurement done
wlan_mgt.ht.mcsset.txmaxss
radiotap.channel.flags.ofdm
radiotap.channel.flags.5ghz done
radiotap.channel.flags.2ghz done
wlan_mgt.fixed.capabilities.spec_man this is realted to 802.11h and dfs done
wlan_mgt.powercap.max done
wlan_mgt.powercap.min done
wlan_mgt.rsn.capabilities.mfpc done
wlan_mgt.extcap.b31 done
wlan_mgt.extcap.b32 done
wlan_mgt.extcap.b46 done
wlan_mgt.tag.number
Maximum MPDU Length = wlan_mgt.vht.capabilities.maxmpdulength done
Supported Channel Width set = wlan_mgt.vht.capabilities.supportedchanwidthset done
Receive LDPC-encoded frames = wlan_mgt.vht.capabilities.rxldpc done
Tansmission of STBC-coded frames = wlan_mgt.vht.capabilities.txstbc done
Support for client to receive from ap that is doing beamforming = wlan_mgt.vht.capabilities.subeamformer done
wlan_mgt.vht.capabilities.beamformerants
wlan_mgt.vht.capabilities.soundingdimensions done
wlan_mgt.vht.capabilities.mubeamformer done
wlan_mgt.vht.capabilities.mubeamformee done
wlan_mgt.tag.oui
wlanmgtfixedcapabilitiesess
radiotapantenna
wlanmgtssid

| Wireshark option name 	| Description 	| Reporting Support 	| Notes 	|   	|
|-----------------------	|-------------	|-------------------	|-------	|---	|
| wlan_mgt.vht.capabilities.short80  | 80 Mhz channel support           	| yes                	|      	|   	|
|                       	|             	|                   	|       	|   	|
|                       	|             	|                   	|       	|   	|
