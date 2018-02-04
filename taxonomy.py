import sys
import os
import logging
import subprocess
import time
import datetime
import os.path
import string
import re


#This change the below to reflect your sysrem
incomingpath = '/root/wifi_taxonomy/testdata/pcaps/' #This is the path where new pcaps will be placed
archivepath = '/root/wifi_taxonomy/testdata/archive/' #This is the path where pcaps what already have been checked will be placed
tmppath = '/data/tmp/' #this is the path for a tmp folder for dwcc to use
DB_FILE = 'dwcc.db'
#you may change the path but please dont change the filename
csvfile = '/data/tmp/dwcc-clients.csv'

def main ():
	tsharker()

def tsharker():
 #This reads the pcaps, pull out the data, and places it into a csv
	#checks for pcap files in incoming

	for fname in os.listdir(incomingpath):
					if fname.endswith('.pcap'):
						pcapfile = incomingpath +fname
						regexvendor = re.compile(r'(.+?(?=GHz))	')
						vendormake = regexvendor.findall(fname)
						subprocess.call("""tshark -r """ + pcapfile + """  -R "wlan.fc.type_subtype == 0x0 or wlan.fc.type_subtype == 0x2" -2 -T fields -e wlan.sa -e wlan.bssid -e radiotap.channel.freq -e wlan_mgt.extcap.b19 -e wlan.fc.protected \
-e wlan_radio.channel -e wlan.fc.pwrmgt -e wlan_mgt.fixed.capabilities.radio_measurement -e wlan_mgt.ht.mcsset.txmaxss \
-e radiotap.channel.flags.ofdm -e radiotap.channel.flags.5ghz -e radiotap.channel.flags.2ghz -e wlan_mgt.fixed.capabilities.spec_man \
-e wlan_mgt.powercap.max -e wlan_mgt.powercap.min -e wlan_mgt.rsn.capabilities.mfpc -e wlan_mgt.extcap.b31 -e wlan_mgt.extcap.b32 -e wlan_mgt.extcap.b46 \
-e wlan_mgt.tag.number -e wlan_mgt.vht.capabilities.maxmpdulength -e wlan_mgt.vht.capabilities.supportedchanwidthset -e wlan_mgt.vht.capabilities.rxldpc \
-e wlan_mgt.vht.capabilities.short80 -e wlan_mgt.vht.capabilities.short160 -e wlan_mgt.vht.capabilities.txstbc -e wlan_mgt.vht.capabilities.subeamformer \
-e wlan_mgt.vht.capabilities.subeamformee -e wlan_mgt.vht.capabilities.beamformerants -e wlan_mgt.vht.capabilities.soundingdimensions -e wlan_mgt.vht.capabilities.mubeamformer \
-e wlan_mgt.vht.capabilities.mubeamformee -e wlan_mgt.tag.oui -e wlan_mgt.fixed.capabilities.ess -e radiotap.antenna \
-e wlan_mgt.extcap.b4 -e wlan_mgt.extcap.b3 -e wlan_mgt.extcap.b2 -e wlan_mgt.extcap.b1 -e wlan_mgt.extcap.b6 -e wlan_mgt.extcap.b8 -e wlan_mgt.extcap.b9 -e wlan_mgt.extcap.b10 -e wlan_mgt.extcap.b11 \
-e wlan_mgt.extcap.b12 -e wlan_mgt.extcap.b13 -e wlan_mgt.extcap.b14 -e wlan_mgt.extcap.b15 -e wlan_mgt.extcap.b16 -e wlan_mgt.extcap.b17 -e wlan_mgt.extcap.b18 -e wlan_mgt.extcap.b20 -e wlan_mgt.extcap.b21 \
-e wlan_mgt.extcap.b22 -e wlan_mgt.extcap.b23 -e wlan_mgt.extcap.b24 -e wlan_mgt.extcap.b25 -e wlan_mgt.extcap.b26 -e wlan_mgt.extcap.b27 -e wlan_mgt.extcap.b28 -e wlan_mgt.extcap.b29 -e wlan_mgt.extcap.b30 \
-e wlan_mgt.extcap.b33 -e wlan_mgt.extcap.b34 -e wlan_mgt.extcap.b35 -e wlan_mgt.extcap.b36 -e wlan_mgt.extcap.b37 -e wlan_mgt.extcap.b38 -e wlan_mgt.extcap.b39 -e wlan_mgt.extcap.b40 -e wlan_mgt.extcap.serv_int_granularity \
-e wlan_mgt.extcap.b44 -e wlan_mgt.extcap.b45 -e wlan_mgt.extcap.b47 -e wlan_mgt.extcap.b48 -e wlan_mgt.extcap.b61 -e wlan_mgt.extcap.b62 -e wlan_mgt.extcap.b63 -e wlan_mgt.vht.capabilities.rxstbc \
-e wlan_mgt.vht.mcsset.rxmcsmap.ss1 -e wlan_mgt.vht.mcsset.rxmcsmap.ss2 -e wlan_mgt.vht.mcsset.rxmcsmap.ss3 -e wlan_mgt.vht.mcsset.rxmcsmap.ss4 \
-e wlan_mgt.vht.mcsset.txmcsmap.ss1 -e wlan_mgt.vht.mcsset.txmcsmap.ss2 -e wlan_mgt.vht.mcsset.txmcsmap.ss3 -e wlan_mgt.vht.mcsset.txmcsmap.ss4 -e wlan_mgt.ssid -e wlan_mgt.ht.mcsset.rxbitmask -e wlan_mgt.ht.ampduparam \
-E separator=+ | sed 's/$/+"""+ str(vendormake) + """/' >> """+ tmppath + """dwcc-testing.csv""", shell=True)
						os.rename(incomingpath +fname, archivepath +fname)

main()


