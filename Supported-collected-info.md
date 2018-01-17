## Supported collected info
The following specifications and features are collected and in the future we will include reports displaying the results of the collection.


|	Wireshark option name 	|	Description	|	Reporting Support	|Notes	|
|-----------------------	|-------------	|-------------------	|-------	|
|	wlan_mgt.vht.capabilities.short80	|	 short Guard Interval 80 Mhz channel support	| yes	|	|
|	wlan_mgt.vht.capabilities.short160	|	short Guard Interval 80 Mhz channel support	|	yes	|	|
|	wlan.fc.protected	|	|	no	|	|
|wlan_mgt.rsn.capabilities.mfpc|802.11W|yes||
|wlan.sa|MAC address of the client|yes||
|wlan.bssid|MAC address of the AP receiving the packet|no||
|radiotap.channel.freq|frequency the client transmitted on|yes||
|wlan_mgt.extcap.b19|BSS Transition(aka 802.11r aka FT)|yes||
|wlan_radio.channel| Channel the client transmitted on|yes||
|wlan.fc.pwrmgt||no||
|wlan_mgt.fixed.capabilities.radio_measurement|802.11k support|yes||
|wlan_mgt.ht.mcsset.txmaxss||no||
|radiotap.channel.flags.ofdm||no||
|radiotap.channel.flags.5ghz| clients found on 5ghz|yes||
|radiotap.channel.flags.2ghz| clients found on 2.4ghz|yes||
|wlan_mgt.fixed.capabilities.spec_man|this is realted to 802.11h and dfs|yes||
|wlan_mgt.powercap.max||yes||
|wlan_mgt.powercap.min||yes||
|wlan_mgt.extcap.b31|interworking this is reated to 802.11u|yes||
|wlan_mgt.extcap.b32|QOS map|yes||
|wlan_mgt.extcap.b46|wnm notification|yes||
|wlan_mgt.tag.number||no||
|wlan_mgt.vht.capabilities.maxmpdulength|Maximum MPDU Length|yes||
|wlan_mgt.vht.capabilities.supportedchanwidthset|Supported Channel Width set|yes||
|wlan_mgt.vht.capabilities.rxldpc|Receive LDPC-encoded frames|yes||
|wlan_mgt.vht.capabilities.txstbc|Tansmission of STBC-coded frames|yes||
|wlan_mgt.vht.capabilities.subeamformer|Support for client to receive from ap that is doing beamforming|yes||
|wlan_mgt.vht.capabilities.beamformerants||no||
|wlan_mgt.vht.capabilities.soundingdimensions||yes||
|wlan_mgt.vht.capabilities.mubeamformer||yes||
|wlan_mgt.vht.capabilities.mubeamformee||yes||
|wlan_mgt.tag.oui||no||
|wlanmgtfixedcapabilitiesess||no||
|radiotapantenna||no||
|wlanmgtssid||no||
