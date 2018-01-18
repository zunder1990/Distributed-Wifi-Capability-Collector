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
|radiotap.channel.flags.ofdm|Orthogonal Frequency-Division Multiplexing OFDM|yes||
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
|wlan.extcap.b4|PSMP Capability related to power mgt |yes||
|wlan.extcap.b3|WAVE indication this is 802.11p|yes||  
|wlan.extcap.b2|Extended Channel Switching this is realted to 802.11y|yes|| 
|wlan.extcap.b1|this is On-demand beacon realted to 802.11p|yes|| 
|wlan.extcap.b6| Scheduled PSMP|yes||
|wlan.extcap.b8|Diagnostic Report |yes|Section 10.23.2.1 of IEEE 802.11-2012|
|wlan.extcap.b9|Multicast Diagnostics|yes||
|wlan.extcap.b10||no||
|wlan.extcap.b11|Flexible Multicast Service |no||
|wlan.extcap.b12|Proxy ARP in 802.11-2012|no||
|wlan.extcap.b13||no||
|wlan.extcap.b14||no||
|wlan.extcap.b15||no||
|wlan.extcap.b16||no||
|wlan.extcap.b17||no||
|wlan.extcap.b18||no||
|wlan.extcap.b20||no||
|wlan.extcap.b21||no||
|wlan.extcap.b22||no||
|wlan.extcap.b23||no||
|wlan.extcap.b24||no||
|wlan.extcap.b25||no||
|wlan.extcap.b26||no||
|wlan.extcap.b27||no||
|wlan.extcap.b28||no||
|wlan.extcap.b29||no||
|wlan.extcap.b30||no||
|wlan.extcap.b33||no||
|wlan.extcap.b34||no||
|wlan.extcap.b35||no||
|wlan.extcap.b36||no||
|wlan.extcap.b37||no||
|wlan.extcap.b38||no||
|wlan.extcap.b39||no||
|wlan.extcap.b40||no||
|wlan.extcap.serv_int_granularity||no||
|wlan.extcap.b44||no||
|wlan.extcap.b45||no||
|wlan.extcap.b46||no||
|wlan.extcap.b47||no||
|wlan.extcap.b48||no||
|wlan.extcap.b61||no||
|wlan.extcap.b62||no||
|wlan.extcap.b63||no||
|wlan.vht.capabilities.rxstbc|realted to Spatial Stream Supported |no|| 
|wlan.vht.mcsset.rxmcsmap.ss2 |realted to Spatial Stream Supported|no||
|wlan.vht.mcsset.rxmcsmap.ss1 |realted to Spatial Stream Supported|no||
|wlan.vht.mcsset.rxmcsmap.ss3 |realted to Spatial Stream Supported|no||
|wlan.vht.mcsset.rxmcsmap.ss4 |realted to Spatial Stream Supported|no||
|wlan.vht.mcsset.txmcsmap.ss1 |realted to Spatial Stream Supported|no||
|wlan.vht.mcsset.txmcsmap.ss2 |realted to Spatial Stream Supported|no||
|wlan.vht.mcsset.txmcsmap.ss1 |realted to Spatial Stream Supported|no||
|wlan.vht.mcsset.txmcsmap.ss2 |realted to Spatial Stream Supported|no||
|wlan.vht.mcsset.txmcsmap.ss3 |realted to Spatial Stream Supported|no||
|wlan.vht.mcsset.txmcsmap.ss4 |realted to Spatial Stream Supported|no||

Great details about some of the above can be found on http://chimera.labs.oreilly.com/books/1234000001739/ch03.html#management_frames
