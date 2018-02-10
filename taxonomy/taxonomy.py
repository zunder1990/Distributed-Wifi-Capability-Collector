import sys
import os
import logging
import subprocess
import time
import datetime
import os.path
import string
import re
import sqlite3
import csv

#This change the below to reflect your sysrem
incomingpath = '/root/wifi_taxonomy/testdata/pcaps/' #This is the path where new pcaps will be placed
archivepath = '/root/wifi_taxonomy/testdata/archive/' #This is the path where pcaps what already have been checked will be placed

DB_FILE = 'dwcc.db'
#here is the setup info for the sqlite db
conn = sqlite3.connect(DB_FILE)
conn.text_factory = str
cursor = conn.cursor()


def main ():
	tsharker()
	dbupdater()

def tsharker():
 #This reads the pcaps, pull out the data, and places it into a csv
	#checks for pcap files in incoming

	for fname in os.listdir(incomingpath):
					if fname.endswith('.pcap'):
						pcapfile = incomingpath +fname
						regexvendor = re.compile(r'(.+?(?=Hz))')
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
-E separator=+ | sed 's/$/+"""+ str(vendormake) + """/' >> dwcc-taxonomy-ass-reass.csv""", shell=True)
						subprocess.call("""tshark -r """ + pcapfile + """  -R "wlan.fc.type_subtype == 0x8" -2 -T fields -e wlan.sa -e wlan.bssid -e radiotap.channel.freq -e wlan_mgt.extcap.b19 -e wlan.fc.protected \
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
-E separator=+ | sed 's/$/+"""+ str(vendormake) + """/' >> dwcc-taxonomy-probe.csv""", shell=True)

						os.rename(incomingpath +fname, archivepath +fname)
						print vendormake
	print "tshark ran on all pcap found"

def dbupdater():
	csvfileprobe = 'dwcc-taxonomy-probe.csv'
#	#this will check for the CSV file, If it is found then import it into the database. If no CSV is found then it move on
	if os.path.isfile(csvfileprobe) and os.access(csvfileprobe, os.R_OK):
		print "probe csv found adding to db"
		subprocess.call("""cat dwcc-taxonomy-probe.csv | sed -e 's/ /-/g' -e 's/[<>"^()@#&!$.*]//g' -e "s/'//g" -e '/^$/d' -e 's/[][]//g' -e 's/[_]//g' >> temp-dwcc-taxonomy-probe.csv""", shell=True)
		os.remove("dwcc-taxonomy-probe.csv")
		os.rename("temp-dwcc-taxonomy-probe.csv", "dwcc-taxonomy-probe.csv")
		csv_probe = csv.reader(file(csvfileprobe), delimiter='+')
		for rowprobe in csv_probe:
			conn.execute('INSERT INTO taxonomyprobe (wlansa, wlanbssid, radiotapchannelfreq, wlanmgtextcapb19, wlanfcprotected, \
wlanradiochannel, wlanfcpwrmgt, wlanmgtfixedcapabilitiesradiomeasurement, wlanmgthtmcssettxmaxss, \
radiotapchannelflagsofdm, radiotapchannelflags5ghz, radiotapchannelflags2ghz, wlanmgtfixedcapabilitiesspecman, \
wlanmgtpowercapmax, wlanmgtpowercapmin, wlanmgtrsncapabilitiesmfpc, wlanmgtextcapb31, wlanmgtextcapb32, wlanmgtextcapb46, \
wlanmgttagnumber, wlanmgtvhtcapabilitiesmaxmpdulength, wlanmgtvhtcapabilitiessupportedchanwidthset, wlanmgtvhtcapabilitiesrxldpc, \
wlanmgtvhtcapabilitiesshort80, wlanmgtvhtcapabilitiesshort160, wlanmgtvhtcapabilitiestxstbc, wlanmgtvhtcapabilitiessubeamformer, \
wlanmgtvhtcapabilitiessubeamformee, wlanmgtvhtcapabilitiesbeamformerants, wlanmgtvhtcapabilitiessoundingdimensions, wlanmgtvhtcapabilitiesmubeamformer, \
wlanmgtvhtcapabilitiesmubeamformee, wlanmgttagoui, wlanmgtfixedcapabilitiesess, radiotapantenna, \
wlanmgtextcapb4, wlanmgtextcapb3, wlanmgtextcapb2, wlanmgtextcapb1, wlanmgtextcapb6, wlanmgtextcapb8, wlanmgtextcapb9, wlanmgtextcapb10, wlanmgtextcapb11, \
wlanmgtextcapb12, wlanmgtextcapb13, wlanmgtextcapb14, wlanmgtextcapb15, wlanmgtextcapb16, wlanmgtextcapb17, wlanmgtextcapb18, wlanmgtextcapb20, wlanmgtextcapb21, \
wlanmgtextcapb22, wlanmgtextcapb23, wlanmgtextcapb24, wlanmgtextcapb25, wlanmgtextcapb26, wlanmgtextcapb27, wlanmgtextcapb28, wlanmgtextcapb29, wlanmgtextcapb30, \
wlanmgtextcapb33, wlanmgtextcapb34, wlanmgtextcapb35, wlanmgtextcapb36, wlanmgtextcapb37, wlanmgtextcapb38, wlanmgtextcapb39, wlanmgtextcapb40, wlanmgtextcapservintgranularity, \
wlanmgtextcapb44, wlanmgtextcapb45, wlanmgtextcapb47, wlanmgtextcapb48, wlanmgtextcapb61, wlanmgtextcapb62, wlanmgtextcapb63, wlanmgtvhtcapabilitiesrxstbc, \
wlanmgtvhtmcssetrxmcsmapss1, wlanmgtvhtmcssetrxmcsmapss2, wlanmgtvhtmcssetrxmcsmapss3, wlanmgtvhtmcssetrxmcsmapss4, \
wlanmgtvhtmcssettxmcsmapss1, wlanmgtvhtmcssettxmcsmapss2, wlanmgtvhtmcssettxmcsmapss3, wlanmgtvhtmcssettxmcsmapss4, wlanmgtssid, wlanmgthtmcssetrxbitmask, wlanmgthtampduparam, vendormake)' \
'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', rowprobe)
		conn.commit()
	csvfileassreass = 'dwcc-taxonomy-ass-reass.csv'
#	#this will check for the CSV file, If it is found then import it into the database. If no CSV is found then it move on
	if os.path.isfile(csvfileprobe) and os.access(csvfileprobe, os.R_OK):
		print "assreass csv found adding to db"
		subprocess.call("""cat dwcc-taxonomy-ass-reass.csv | sed -e 's/ /-/g' -e 's/[<>"^()@#&!$.*]//g' -e "s/'//g" -e '/^$/d' -e 's/[][]//g' -e 's/[_]//g' >> temp-dwcc-taxonomy-ass-reass.csv""", shell=True)
		os.remove("dwcc-taxonomy-ass-reass.csv")
		os.rename("temp-dwcc-taxonomy-ass-reass.csv", "dwcc-taxonomy-ass-reass.csv")
		csv_assreass = csv.reader(file(csvfileassreass), delimiter='+')
		for rowassreass in csv_assreass:
			conn.execute('INSERT INTO taxonomyassreass(wlansa, wlanbssid, radiotapchannelfreq, wlanmgtextcapb19, wlanfcprotected, \
wlanradiochannel, wlanfcpwrmgt, wlanmgtfixedcapabilitiesradiomeasurement, wlanmgthtmcssettxmaxss, \
radiotapchannelflagsofdm, radiotapchannelflags5ghz, radiotapchannelflags2ghz, wlanmgtfixedcapabilitiesspecman, \
wlanmgtpowercapmax, wlanmgtpowercapmin, wlanmgtrsncapabilitiesmfpc, wlanmgtextcapb31, wlanmgtextcapb32, wlanmgtextcapb46, \
wlanmgttagnumber, wlanmgtvhtcapabilitiesmaxmpdulength, wlanmgtvhtcapabilitiessupportedchanwidthset, wlanmgtvhtcapabilitiesrxldpc, \
wlanmgtvhtcapabilitiesshort80, wlanmgtvhtcapabilitiesshort160, wlanmgtvhtcapabilitiestxstbc, wlanmgtvhtcapabilitiessubeamformer, \
wlanmgtvhtcapabilitiessubeamformee, wlanmgtvhtcapabilitiesbeamformerants, wlanmgtvhtcapabilitiessoundingdimensions, wlanmgtvhtcapabilitiesmubeamformer, \
wlanmgtvhtcapabilitiesmubeamformee, wlanmgttagoui, wlanmgtfixedcapabilitiesess, radiotapantenna, \
wlanmgtextcapb4, wlanmgtextcapb3, wlanmgtextcapb2, wlanmgtextcapb1, wlanmgtextcapb6, wlanmgtextcapb8, wlanmgtextcapb9, wlanmgtextcapb10, wlanmgtextcapb11, \
wlanmgtextcapb12, wlanmgtextcapb13, wlanmgtextcapb14, wlanmgtextcapb15, wlanmgtextcapb16, wlanmgtextcapb17, wlanmgtextcapb18, wlanmgtextcapb20, wlanmgtextcapb21, \
wlanmgtextcapb22, wlanmgtextcapb23, wlanmgtextcapb24, wlanmgtextcapb25, wlanmgtextcapb26, wlanmgtextcapb27, wlanmgtextcapb28, wlanmgtextcapb29, wlanmgtextcapb30, \
wlanmgtextcapb33, wlanmgtextcapb34, wlanmgtextcapb35, wlanmgtextcapb36, wlanmgtextcapb37, wlanmgtextcapb38, wlanmgtextcapb39, wlanmgtextcapb40, wlanmgtextcapservintgranularity, \
wlanmgtextcapb44, wlanmgtextcapb45, wlanmgtextcapb47, wlanmgtextcapb48, wlanmgtextcapb61, wlanmgtextcapb62, wlanmgtextcapb63, wlanmgtvhtcapabilitiesrxstbc, \
wlanmgtvhtmcssetrxmcsmapss1, wlanmgtvhtmcssetrxmcsmapss2, wlanmgtvhtmcssetrxmcsmapss3, wlanmgtvhtmcssetrxmcsmapss4, \
wlanmgtvhtmcssettxmcsmapss1, wlanmgtvhtmcssettxmcsmapss2, wlanmgtvhtmcssettxmcsmapss3, wlanmgtvhtmcssettxmcsmapss4, wlanmgtssid, wlanmgthtmcssetrxbitmask, wlanmgthtampduparam, vendormake)' \
'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', rowassreass)
		conn.commit()
						
						
						
						
main()

 