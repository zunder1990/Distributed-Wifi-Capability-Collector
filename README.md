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
* CPU = Raspberry Pi 3 $37.00 https://www.amazon.com/Raspberry-Pi-RASPBERRYPI3-MODB-1GB-Model-Motherboard/dp/B01CD5VC92/ref=sr_1_3?s=pc&ie=UTF8&qid=1516630839&sr=1-3&keywords=raspberry+pi+3
* Wireless = 4x RaLink RT3572 $8.89 each or $35.56 total  https://www.aliexpress.com/item/RaLink-RT3572-2-4GHz-5-0GHz-300Mbps-WiFi-USB-Adapter-PCB-Module-Wireless-WiFi-Adapter-with/32815492744.html
* SD card = 32GB $13.97 https://www.aliexpress.com/item/real-capacity-100-Sandisk-Micro-SD-card-Class10-8gb-16gb-32gb-64gb-128gb-80Mb-s-Original/32691928032.html
* case = $15 https://www.ebay.com/itm/Black-Aluminum-Project-Box-Enclosure-Case-Electronic-DIY-203x144x68mm-Big/250826353904
* POE splitter = $7.59 https://www.aliexpress.com/item/DSLRKIT-Active-PoE-Splitter-48V-to-5V-5-2V-2-4A-USB-TYPE-A-Female-802/32819476796.html
* Cost = $109.12
 
## Status LEDs
The follwing LEDs have been tested with Raspberry Pi 3. To use the status LEDs you must make sure that the VAR "iamapi" is set to 1
* Gpin 6 is on when sniffer is running
* Gpin 13 is on when the sensor can ping google.com
* Pin 1 will come on when the device boots

## Wiring LEDs on PI
This will be updated at a later time.

## Demo 
https://server.zachunderwood.me/display.html

 ## Misc
 Used to pull the packets for one MAC
 * tshark -r bigpcap.pcap -R "wlan.sa == xx:xx:xx:xx:xx:xx" -2 -w temp.pcap
 
 * iw reg get 
 * iw reg set US
 * rename "s/\s+/-/g" *
 * rename "s/\+/plus/g" *
 * rename "s/\()//g" *

 

