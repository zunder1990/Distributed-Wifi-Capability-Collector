# Distributed-Wifi-Capability-Collector(DWCC)
This project is designed to passively collect WIFI(802.11) management frames from inexpensive sensors distruted to see what features and specifications your WIFI clients support.

The plan is to collect pcaps then analyze them extracting the relevant data on the sensor.  Then sending it to a central database.  

## Supported collected info
See Supported-collected-info.md page for list



Got ideas from https://github.com/Geovation/wifispy and https://github.com/roobixx/harbinger

## Hardware examples
__Example 1:__
* Wireless=Alfa AWUS051NH ($70)
* CPU=Raspberry Pi 3 ($39)
* You would still SD card, case,  and power supply
* Cost=~$150

__Example 2:__
This hareware needs to be tested. I have a kit coming for testing
* CPU = Orange Pi PC $16.50 https://www.aliexpress.com/item/Orange-Pi-PC-set-1-Orange-Pi-PC-USB-to-DC-4-0MM-1-7MM-power/32451459094.html
* Wireless = 3x RaLink RT3572 $26.67 https://www.aliexpress.com/item/RaLink-RT3572-2-4GHz-5-0GHz-300Mbps-WiFi-USB-Adapter-PCB-Module-Wireless-WiFi-Adapter-with/32815492744.html
* SD card = 16GB $8.08 https://www.aliexpress.com/item/real-capacity-100-Sandisk-Micro-SD-card-Class10-8gb-16gb-32gb-64gb-128gb-80Mb-s-Original/32691928032.html
* case = $13.83 https://www.aliexpress.com/item/Waterproof-Clear-Cover-Plastic-Electronic-Project-Box-265x185x125mm/32798563434.html
* usb cables = $1.46(3 of them) https://www.aliexpress.com/item/USB-Female-to-Male-Extension-Cable-for-3pcs-lot-Short-USB-2-0-A-Female-To/32796757499.html
* POE splitter = $7.59 https://www.aliexpress.com/item/DSLRKIT-Active-PoE-Splitter-48V-to-5V-5-2V-2-4A-USB-TYPE-A-Female-802/32819476796.html
* Cost = $74.13
 
## Status LEDs
The follwing LEDs have been tested with Raspberry Pi 3. To use the status LEDs you must make sure that the VAR "iamapi" is set to 1
* Gpin 6 is on when sniffer is running
* Gpin 13 is on when the sensor can ping google.com
* Pin 1 will come on when the device boots

## Wiring LEDs on PI
This will be updated at a later time.


 ## Misc
 Used to pull the packets for one MAC
 * tshark -r bigpcap.pcap -R "wlan.sa == xx:xx:xx:xx:xx:xx" -2 -w temp.pcap
 
 * iw reg get 
 * iw reg set US
 

