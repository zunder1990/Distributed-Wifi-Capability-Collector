#!/usr/bin/python
import sys
import os
import subprocess
import time
import csv
import os.path
from manuf import manuf
import string
import re
import mysql.connector
import config

#This change the below to reflect your system
incomingpath = '/data/incoming/' #This is the path where new pcaps will be placed
archivepath = '/data/archive/' #This is the path where pcaps what already have been checked will be placed
tmppath = '/data/tmp/' #this is the path for a tmp folder for dwcc to use
DB_FILE = 'dwcc.db'
#you may change the path but please dont change the filename
csvfile = '/data/tmp/dwcc-clients.csv'

#here is the setup info for the sqlite db
#conn = sqlite3.connect(DB_FILE)
#conn.text_factory = str
#cursor = conn.cursor()

mydb = mysql.connector.connect(
  host="10.1.0.7",
  user= config.username,
  password= config.password,
  database="dwcc"
)

mycursor = mydb.cursor()



#this is the main fuction
def start():
	preflightcheck()
	while True:
		try:
			tsharker()
			dbupdater()
#			dedup()
#			dbconverter()
#			heatmapprep()
#			heatmapping()
##			mergecap()
#			macaddressconverterclient()
#			macaddressconverterap()
#			macaddressconverterprobe()
#			taxonomyreporting()
			time.sleep(30)#seconds
		except KeyboardInterrupt: sys.exit()

def preflightcheck():
	if not os.path.exists(incomingpath):
		os.makedirs(incomingpath)
	if not os.path.exists(archivepath):
		os.makedirs(archivepath)
	if not os.path.exists(tmppath):
		os.makedirs(tmppath)

"""
#this will take a look at the mac address of the transmitter and
def dedup():
	mycursor.execute('DELETE FROM dwccincoming WHERE ID NOT IN (SELECT min(ID) FROM dwccincoming GROUP BY wlansa, radiotapchannelflags2ghz, radiotapchannelflags2ghz);')
	mycursor.execute('DELETE FROM dwccincomingprobe WHERE ID NOT IN (SELECT min(ID) FROM dwccincomingprobe GROUP BY wlansa, radiotapchannelflags2ghz, radiotapchannelflags2ghz);')
	mycursor.execute('DELETE FROM dwccap WHERE ID NOT IN (SELECT min(ID) FROM dwccap GROUP BY wlanbssid, wlanmgtssid);')
	print "finish dedup"
"""

"""
def dbconverter():
	mycursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessoundingdimensions = '1' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000001';")
	mycursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessoundingdimensions = '0' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000000';")
	mycursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessoundingdimensions = '3' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000002';")
	mycursor.execute("UPDATE dwccincoming SET wlansaconverted = 'vendornotfound' WHERE wlansaconverted  = 'None';")
	mycursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiesmaxmpdulength = '11454' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000002';")
	mycursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiesmaxmpdulength = '7991' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000001';")
	mycursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiesmaxmpdulength = '3895' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000000';")
	mycursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessupportedchanwidthset = '0' WHERE wlanmgtvhtcapabilitiessupportedchanwidthset  = '0x00000000';")
	mycursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessupportedchanwidthset = '1' WHERE wlanmgtvhtcapabilitiessupportedchanwidthset  = '0x00000001';")
	mycursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessupportedchanwidthset = '2' WHERE wlanmgtvhtcapabilitiessupportedchanwidthset  = '0x00000002';")
	mycursor.execute("UPDATE dwccap SET wlansaconverted = 'vendornotfound' WHERE wlansaconverted  = 'None';")
	mycursor.execute("UPDATE dwccap SET wlanmgtssid = 'SSIDnotfound' WHERE wlanmgtssid is null or wlanmgtssid = '';")
	mycursor.execute("UPDATE dwccincomingprobe SET wlansaconverted = 'vendornotfound' WHERE wlansaconverted  = 'None';")
	mycursor.execute("UPDATE dwccincomingprobe SET wlanmgtvhtcapabilitiessoundingdimensions = '1' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000001';")
	mycursor.execute("UPDATE dwccincomingprobe SET wlanmgtvhtcapabilitiessoundingdimensions = '0' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000000';")
	mycursor.execute("UPDATE dwccincomingprobe SET wlanmgtvhtcapabilitiessoundingdimensions = '3' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000002';")
	mycursor.execute("UPDATE dwccincomingprobe SET wlanmgtvhtcapabilitiesmaxmpdulength = '11454' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000002';")
	mycursor.execute("UPDATE dwccincomingprobe SET wlanmgtvhtcapabilitiesmaxmpdulength = '7991' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000001';")
	mycursor.execute("UPDATE dwccincomingprobe SET wlanmgtvhtcapabilitiesmaxmpdulength = '3895' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000000';")
	mycursor.execute("UPDATE dwccincomingprobe SET wlanmgtvhtcapabilitiessupportedchanwidthset = '0' WHERE wlanmgtvhtcapabilitiessupportedchanwidthset  = '0x00000000';")
	mycursor.execute("UPDATE dwccincomingprobe SET wlanmgtvhtcapabilitiessupportedchanwidthset = '1' WHERE wlanmgtvhtcapabilitiessupportedchanwidthset  = '0x00000001';")
	mycursor.execute("UPDATE dwccincomingprobe SET wlanmgtvhtcapabilitiessupportedchanwidthset = '2' WHERE wlanmgtvhtcapabilitiessupportedchanwidthset  = '0x00000002';")
"""
#def mergecap():
#	subprocess.call('mergecap -w /nfs/$HOSTNAME/bigpcap.pcap /nfs/$HOSTNAME/archive/*.pcap', shell=True)
#	subprocess.call('rm -f /nfs/$HOSTNAME/archive/*.pcap', shell=True)


def tsharker():
 #This reads the pcaps, pull out the data, and places it into a csv
	#checks for pcap files in incoming

	for fname in os.listdir(incomingpath):
					if fname.endswith('.pcap'):
						pcapfile = incomingpath +fname
						regexhostname = re.compile(r'^[A-Za-z0-9_.]+')
						hostnameonly = regexhostname.findall(fname)
						regexyear = re.compile(r'([0-9]{4}\-[0-9]{2}\-[0-9]{2}\_[0-9]{2}\.[0-9]{2}\.[0-9]{2})')
						timestamp = regexyear.findall(fname)
						subprocess.call('tshark -r ' + pcapfile + '   -R "wlan.fc.type_subtype == 0x0 or wlan.fc.type_subtype == 0x2" -2 -T fields -e wlan.sa -e wlan.bssid -e radiotap.channel.freq -e wlan.extcap.b19 -e wlan.fc.protected \
-e wlan_radio.channel -e wlan.fc.pwrmgt -e wlan.fixed.capabilities.radio_measurement -e wlan.ht.mcsset.txmaxss \
-e radiotap.channel.flags.ofdm -e radiotap.channel.flags.5ghz -e radiotap.channel.flags.2ghz -e wlan.fixed.capabilities.spec_man \
-e wlan.powercap.max -e wlan.powercap.min -e wlan.rsn.capabilities.mfpc -e wlan.extcap.b31 -e wlan.extcap.b32 -e wlan.extcap.b46 \
-e wlan.tag.number -e wlan.vht.capabilities.maxmpdulength -e wlan.vht.capabilities.supportedchanwidthset -e wlan.vht.capabilities.rxldpc \
-e wlan.vht.capabilities.short80 -e wlan.vht.capabilities.short160 -e wlan.vht.capabilities.txstbc -e wlan.vht.capabilities.subeamformer \
-e wlan.vht.capabilities.subeamformee -e wlan.vht.capabilities.soundingdimensions -e wlan.vht.capabilities.mubeamformer \
-e wlan.vht.capabilities.mubeamformee -e wlan.tag.oui -e wlan.fixed.capabilities.ess -e radiotap.antenna \
-e wlan.extcap.b4 -e wlan.extcap.b3 -e wlan.extcap.b2 -e wlan.extcap.b1 -e wlan.extcap.b6 -e wlan.extcap.b8 -e wlan.extcap.b9 -e wlan.extcap.b10 -e wlan.extcap.b11 \
-e wlan.extcap.b12 -e wlan.extcap.b13 -e wlan.extcap.b14 -e wlan.extcap.b15 -e wlan.extcap.b16 -e wlan.extcap.b17 -e wlan.extcap.b18 -e wlan.extcap.b20 -e wlan.extcap.b21 \
-e wlan.extcap.b22 -e wlan.extcap.b23 -e wlan.extcap.b24 -e wlan.extcap.b25 -e wlan.extcap.b26 -e wlan.extcap.b27 -e wlan.extcap.b28 -e wlan.extcap.b29 -e wlan.extcap.b30 \
-e wlan.extcap.b33 -e wlan.extcap.b34 -e wlan.extcap.b35 -e wlan.extcap.b36 -e wlan.extcap.b37 -e wlan.extcap.b38 -e wlan.extcap.b39 -e wlan.extcap.b40 -e wlan.extcap.serv_int_granularity \
-e wlan.extcap.b44 -e wlan.extcap.b45 -e wlan.extcap.b47 -e wlan.extcap.b48 -e wlan.extcap.b61 -e wlan.extcap.b62 -e wlan.extcap.b63 -e wlan.vht.capabilities.rxstbc \
-e wlan.vht.mcsset.rxmcsmap.ss1 -e wlan.vht.mcsset.rxmcsmap.ss2 -e wlan.vht.mcsset.rxmcsmap.ss3 -e wlan.vht.mcsset.rxmcsmap.ss4 \
-e wlan.vht.mcsset.txmcsmap.ss1 -e wlan.vht.mcsset.txmcsmap.ss2 -e wlan.vht.mcsset.txmcsmap.ss3 -e wlan.vht.mcsset.txmcsmap.ss4 -e wlan.ssid -e wlan.ht.mcsset.rxbitmask -e wlan.ht.ampduparam \
-E separator=+ >> ' + tmppath + 'dwcc-clients.csv', shell=True)
						subprocess.call('tshark -r ' + pcapfile + '   -R "wlan.fc.type_subtype == 0x8" -2 -T fields -e wlan_radio.channel -e wlan.ssid -e wlan.bssid -E separator=+ >> ' + tmppath + 'dwcc-ap.csv', shell=True)
						subprocess.call("""tshark -r """ + pcapfile + """   -R "wlan.fc.type_subtype == 0x0 or wlan.fc.type_subtype == 0x2 or wlan.fc.type_subtype == 0x4" -2 -T fields -e wlan.sa -e wlan.bssid \
-e wlan_radio.signal_dbm -E separator=+ | sed 's/$/+"""+ str(hostnameonly) + """+"""+ str(timestamp) +"""/' >> """+ tmppath + """dwcc-heatmap.csv""", shell=True)
						subprocess.call('tshark -r ' + pcapfile + '   -R "wlan.fc.type_subtype == 0x4" -2 -T fields -e wlan.sa -e wlan.bssid -e radiotap.channel.freq -e wlan.extcap.b19 -e wlan.fc.protected \
-e wlan_radio.channel -e wlan.fc.pwrmgt -e wlan.fixed.capabilities.radio_measurement -e wlan.ht.mcsset.txmaxss \
-e radiotap.channel.flags.ofdm -e radiotap.channel.flags.5ghz -e radiotap.channel.flags.2ghz -e wlan.fixed.capabilities.spec_man \
-e wlan.powercap.max -e wlan.powercap.min -e wlan.rsn.capabilities.mfpc -e wlan.extcap.b31 -e wlan.extcap.b32 -e wlan.extcap.b46 \
-e wlan.tag.number -e wlan.vht.capabilities.maxmpdulength -e wlan.vht.capabilities.supportedchanwidthset -e wlan.vht.capabilities.rxldpc \
-e wlan.vht.capabilities.short80 -e wlan.vht.capabilities.short160 -e wlan.vht.capabilities.txstbc -e wlan.vht.capabilities.subeamformer \
-e wlan.vht.capabilities.subeamformee -e wlan.vht.capabilities.soundingdimensions -e wlan.vht.capabilities.mubeamformer \
-e wlan.vht.capabilities.mubeamformee -e wlan.tag.oui -e wlan.fixed.capabilities.ess -e radiotap.antenna \
-e wlan.extcap.b4 -e wlan.extcap.b3 -e wlan.extcap.b2 -e wlan.extcap.b1 -e wlan.extcap.b6 -e wlan.extcap.b8 -e wlan.extcap.b9 -e wlan.extcap.b10 -e wlan.extcap.b11 \
-e wlan.extcap.b12 -e wlan.extcap.b13 -e wlan.extcap.b14 -e wlan.extcap.b15 -e wlan.extcap.b16 -e wlan.extcap.b17 -e wlan.extcap.b18 -e wlan.extcap.b20 -e wlan.extcap.b21 \
-e wlan.extcap.b22 -e wlan.extcap.b23 -e wlan.extcap.b24 -e wlan.extcap.b25 -e wlan.extcap.b26 -e wlan.extcap.b27 -e wlan.extcap.b28 -e wlan.extcap.b29 -e wlan.extcap.b30 \
-e wlan.extcap.b33 -e wlan.extcap.b34 -e wlan.extcap.b35 -e wlan.extcap.b36 -e wlan.extcap.b37 -e wlan.extcap.b38 -e wlan.extcap.b39 -e wlan.extcap.b40 -e wlan.extcap.serv_int_granularity \
-e wlan.extcap.b44 -e wlan.extcap.b45 -e wlan.extcap.b47 -e wlan.extcap.b48 -e wlan.extcap.b61 -e wlan.extcap.b62 -e wlan.extcap.b63 -e wlan.vht.capabilities.rxstbc \
-e wlan.vht.mcsset.rxmcsmap.ss1 -e wlan.vht.mcsset.rxmcsmap.ss2 -e wlan.vht.mcsset.rxmcsmap.ss3 -e wlan.vht.mcsset.rxmcsmap.ss4 \
-e wlan.vht.mcsset.txmcsmap.ss1 -e wlan.vht.mcsset.txmcsmap.ss2 -e wlan.vht.mcsset.txmcsmap.ss3 -e wlan.vht.mcsset.txmcsmap.ss4 -e wlan.ht.mcsset.rxbitmask -e wlan.ht.ampduparam \
-E separator=+ >> ' + tmppath + 'dwcc-probe.csv', shell=True)
			#this below will move the pcap into the archive folder
						os.rename(incomingpath +fname, archivepath +fname)
						print "pcap found and tshark has ran"
					else:
						print "No pcap found waiting 5 mins to rerun"

def macaddressconverterclient():
	p = manuf.MacParser(update=True)
	mycursor.execute("""SELECT wlansa from dwccincoming WHERE wlansaconverted IS NULL OR wlansaconverted = '' limit 1;""")
	mactochange = mycursor.fetchone()

	print "The mac that will be changed", mactochange
	if mactochange is None:
		print "all MAC matched to vendors"
	else:
		#This below will remove the punctuation for the VAR
		mactochange = ''.join(c for c in mactochange if c not in string.punctuation)
		changedmac = p.get_manuf(mactochange)
		changedmacstr = str(changedmac)
		mactochangestr = str(mactochange)
		#This below will write the mac vendor back to the database
		mycursor.execute("UPDATE dwccincoming SET wlansaconverted = "+ `changedmacstr` +" WHERE wlansa  = "+ `mactochangestr` +"   ;")
		macaddressconverterclient()



def macaddressconverterap():
	for i in range(50):
		p = manuf.MacParser(update=True)
		mycursor.execute("""SELECT wlanbssid from dwccap WHERE wlansaconverted IS NULL OR wlansaconverted = '' limit 1;""")
		mactochange = mycursor.fetchone()
	
		print "The ap mac that will be changed", mactochange
		if mactochange is None:
			print "all ap MAC matched to vendors"
			return
		else:
			#This below will remove the punctuation for the VAR
			mactochange = ''.join(c for c in mactochange if c not in string.punctuation)
			changedmac = p.get_manuf(mactochange)
			changedmacstr = str(changedmac)
			mactochangestr = str(mactochange)
			#This below will write the mac vendor back to the database
			mycursor.execute("UPDATE dwccap SET wlansaconverted = "+ `changedmacstr` +" WHERE wlanbssid  = "+ `mactochangestr` +"   ;")
#			macaddressconverterap()
	print "finished a round up to 50 AP mac"


	

def macaddressconverterprobe():
	for i in range(50):
		p = manuf.MacParser(update=True)
		mycursor.execute("""SELECT wlansa from dwccincomingprobe WHERE wlansaconverted IS NULL OR wlansaconverted = '' limit 1;""")
		mactochange = mycursor.fetchone()
	
		print "The probe mac that will be changed", mactochange
		if mactochange is None:
			print "all probe MAC matched to vendors"
			return
		else:
			#This below will remove the punctuation for the VAR
			mactochange = ''.join(c for c in mactochange if c not in string.punctuation)
			changedmac = p.get_manuf(mactochange)
			changedmacstr = str(changedmac)
			mactochangestr = str(mactochange)
			#This below will write the mac vendor back to the database
			mycursor.execute("UPDATE dwccincomingprobe SET wlansaconverted = "+ `changedmacstr` +" WHERE wlansa  = "+ `mactochangestr` +"   ;")
#			macaddressconverterap()
	print "finished a round up to 50 probe mac"
		
		

#This will take the CSV and place it into the db
def dbupdater():
	csvfileclient = '/data/tmp/dwcc-clients.csv'
#	#this will check for the CSV file, If it is found then import it into the database. If no CSV is found then it move on
	if os.path.isfile(csvfileclient) and os.access(csvfileclient, os.R_OK):
		print "csv found adding to db"
		subprocess.call("""awk '!seen[$0]++' /data/tmp/dwcc-clients.csv >> /data/tmp/temp-dwcc-clients.csv""", shell=True)
		os.remove("/data/tmp/dwcc-clients.csv")
		os.rename("/data/tmp/temp-dwcc-clients.csv", "/data/tmp/dwcc-clients.csv")
		csv_data = csv.reader(file(csvfileclient), delimiter='+')
		for row in csv_data:
			mycursor.execute('INSERT INTO dwccincoming(wlansa, wlanbssid, radiotapchannelfreq, wlanmgtextcapb19, wlanfcprotected, \
wlanradiochannel, wlanfcpwrmgt, wlanmgtfixedcapabilitiesradiomeasurement, wlanmgthtmcssettxmaxss, \
radiotapchannelflagsofdm, radiotapchannelflags5ghz, radiotapchannelflags2ghz, wlanmgtfixedcapabilitiesspecman, \
wlanmgtpowercapmax, wlanmgtpowercapmin, wlanmgtrsncapabilitiesmfpc, wlanmgtextcapb31, wlanmgtextcapb32, wlanmgtextcapb46, \
wlanmgttagnumber, wlanmgtvhtcapabilitiesmaxmpdulength, wlanmgtvhtcapabilitiessupportedchanwidthset, wlanmgtvhtcapabilitiesrxldpc, \
wlanmgtvhtcapabilitiesshort80, wlanmgtvhtcapabilitiesshort160, wlanmgtvhtcapabilitiestxstbc, wlanmgtvhtcapabilitiessubeamformer, \
wlanmgtvhtcapabilitiessubeamformee, wlanmgtvhtcapabilitiessoundingdimensions, wlanmgtvhtcapabilitiesmubeamformer, \
wlanmgtvhtcapabilitiesmubeamformee, wlanmgttagoui,  wlanmgtfixedcapabilitiesess, radiotapantenna, \
wlanmgtextcapb4, wlanmgtextcapb3, wlanmgtextcapb2, wlanmgtextcapb1, wlanmgtextcapb6, wlanmgtextcapb8, wlanmgtextcapb9, wlanmgtextcapb10, wlanmgtextcapb11, wlanmgtextcapb12, \
wlanmgtextcapb13, wlanmgtextcapb14, wlanmgtextcapb15, wlanmgtextcapb16, wlanmgtextcapb17, wlanmgtextcapb18, wlanmgtextcapb20, wlanmgtextcapb21, wlanmgtextcapb22, wlanmgtextcapb23, \
wlanmgtextcapb24, wlanmgtextcapb25, wlanmgtextcapb26, wlanmgtextcapb27, wlanmgtextcapb28, wlanmgtextcapb29, wlanmgtextcapb30, wlanmgtextcapb33, wlanmgtextcapb34, wlanmgtextcapb35, \
wlanmgtextcapb36, wlanmgtextcapb37, wlanmgtextcapb38, wlanmgtextcapb39, wlanmgtextcapb40, wlanmgtextcapservintgranularity, wlanmgtextcapb44, wlanmgtextcapb45, wlanmgtextcapb47, \
wlanmgtextcapb48, wlanmgtextcapb61, wlanmgtextcapb62, wlanmgtextcapb63, wlanmgtvhtcapabilitiesrxstbc, wlanmgtvhtmcssetrxmcsmapss1, wlanmgtvhtmcssetrxmcsmapss2, wlanmgtvhtmcssetrxmcsmapss3, \
wlanmgtvhtmcssetrxmcsmapss4, wlanmgtvhtmcssettxmcsmapss1, wlanmgtvhtmcssettxmcsmapss2, wlanmgtvhtmcssettxmcsmapss3, wlanmgtvhtmcssettxmcsmapss4, wlanmgtssid, wlanmgthtmcssetrxbitmask, wlanmgthtampduparam)' \
'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', row)

#This will remove the file after it is added to the db
		os.remove(csvfileclient)
		print "done with dbupdate for client waiting for next run"
	else:
		print"csv client not found will retry"



	csvfileprobe = '/data/tmp/dwcc-probe.csv'
#	#this will check for the CSV file, If it is found then import it into the database. If no CSV is found then it move on
	if os.path.isfile(csvfileprobe) and os.access(csvfileprobe, os.R_OK):
		print "probe csv found adding to db"
		subprocess.call("""awk '!seen[$0]++' /data/tmp/dwcc-probe.csv | sed -e 's/ /-/g' -e 's/[<>"^()@#&!$.*]//g' -e "s/'//g" -e '/^$/d' -e 's/[][]//g' -e 's/[-_]//g' >> /data/tmp/temp-dwcc-probe.csv""", shell=True)
		os.remove("/data/tmp/dwcc-probe.csv")
		os.rename("/data/tmp/temp-dwcc-probe.csv", "/data/tmp/dwcc-probe.csv")
		csv_probe = csv.reader(file(csvfileprobe), delimiter='+')
		for rowprobe in csv_probe:
			mycursor.execute('INSERT INTO dwccincomingprobe (wlansa, wlanbssid, radiotapchannelfreq, wlanmgtextcapb19, wlanfcprotected, \
wlanradiochannel, wlanfcpwrmgt, wlanmgtfixedcapabilitiesradiomeasurement, wlanmgthtmcssettxmaxss, \
radiotapchannelflagsofdm, radiotapchannelflags5ghz, radiotapchannelflags2ghz, wlanmgtfixedcapabilitiesspecman, \
wlanmgtpowercapmax, wlanmgtpowercapmin, wlanmgtrsncapabilitiesmfpc, wlanmgtextcapb31, wlanmgtextcapb32, wlanmgtextcapb46, \
wlanmgttagnumber, wlanmgtvhtcapabilitiesmaxmpdulength, wlanmgtvhtcapabilitiessupportedchanwidthset, wlanmgtvhtcapabilitiesrxldpc, \
wlanmgtvhtcapabilitiesshort80, wlanmgtvhtcapabilitiesshort160, wlanmgtvhtcapabilitiestxstbc, wlanmgtvhtcapabilitiessubeamformer, \
wlanmgtvhtcapabilitiessubeamformee, wlanmgtvhtcapabilitiessoundingdimensions, wlanmgtvhtcapabilitiesmubeamformer, \
wlanmgtvhtcapabilitiesmubeamformee, wlanmgttagoui,  wlanmgtfixedcapabilitiesess, radiotapantenna, \
wlanmgtextcapb4, wlanmgtextcapb3, wlanmgtextcapb2, wlanmgtextcapb1, wlanmgtextcapb6, wlanmgtextcapb8, wlanmgtextcapb9, wlanmgtextcapb10, wlanmgtextcapb11, wlanmgtextcapb12, \
wlanmgtextcapb13, wlanmgtextcapb14, wlanmgtextcapb15, wlanmgtextcapb16, wlanmgtextcapb17, wlanmgtextcapb18, wlanmgtextcapb20, wlanmgtextcapb21, wlanmgtextcapb22, wlanmgtextcapb23, \
wlanmgtextcapb24, wlanmgtextcapb25, wlanmgtextcapb26, wlanmgtextcapb27, wlanmgtextcapb28, wlanmgtextcapb29, wlanmgtextcapb30, wlanmgtextcapb33, wlanmgtextcapb34, wlanmgtextcapb35, \
wlanmgtextcapb36, wlanmgtextcapb37, wlanmgtextcapb38, wlanmgtextcapb39, wlanmgtextcapb40, wlanmgtextcapservintgranularity, wlanmgtextcapb44, wlanmgtextcapb45, wlanmgtextcapb47, \
wlanmgtextcapb48, wlanmgtextcapb61, wlanmgtextcapb62, wlanmgtextcapb63, wlanmgtvhtcapabilitiesrxstbc, wlanmgtvhtmcssetrxmcsmapss1, wlanmgtvhtmcssetrxmcsmapss2, wlanmgtvhtmcssetrxmcsmapss3, \
wlanmgtvhtmcssetrxmcsmapss4, wlanmgtvhtmcssettxmcsmapss1, wlanmgtvhtmcssettxmcsmapss2, wlanmgtvhtmcssettxmcsmapss3, wlanmgtvhtmcssettxmcsmapss4, wlanmgthtmcssetrxbitmask, wlanmgthtampduparam)' \
'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', rowprobe)



#This will remove the file after it is added to the db
		os.remove(csvfileprobe)
		print "done with dbupdate for probe waiting for next run"
	else:
		print"csv probe not found will retry"
		
		

		
	csvfileap = '/data/tmp/dwcc-ap.csv'
	#this will check for the CSV file, If it is found then import it into the database. If no CSV is found then it move on
	if os.path.isfile(csvfileap) and os.access(csvfileap, os.R_OK):
		print "ap csv found adding to db"
		#awk '!seen[$0]++' will dedup without having to sort
		#sed -e 's/ /-/g' -e 's/[<>"^()@#&!$.,]//g' -e "s/'//g" -e '/^$/d' will special characters
        #sed -n 's/$/+/' will add a + to end of each line to allow the csp to be imported into the db
		subprocess.call("""cat /data/tmp/dwcc-ap.csv | awk '!seen[$0]++' | sed -e 's/ /-/g' -e 's/[<>"^()@#&!$.,]//g' -e "s/'//g" -e '/^$/d' | awk 'BEGIN{FS=OFS="+"} NF==4 {$0=$1 OFS $2 $3 OFS $4} {print}' | sed -n 's/$/+/' >> /data/tmp/temp-dwcc-ap.csv """, shell=True)
		os.remove("/data/tmp/dwcc-ap.csv")
		os.rename("/data/tmp/temp-dwcc-ap.csv", "/data/tmp/dwcc-ap.csv")
		csv_dataap = csv.reader(file(csvfileap), delimiter='+')
		for rowap in csv_dataap:
			mycursor.execute('INSERT INTO dwccap (wlanradiochannel, wlanmgtssid, wlanbssid)' 'VALUES (?,?,?)', rowap)



#This will remove the file after it is added to the db
		os.remove(csvfileap)
		print "done with dbupdate for ap waiting for next run"
	else:
		print"csv ap not found will retry"


	csvheatmap = '/data/tmp/dwcc-heatmap.csv'
	#this will check for the CSV file, If it is found then import it into the database. If no CSV is found then it move on
	if os.path.isfile(csvheatmap) and os.access(csvheatmap, os.R_OK):
		print "heatmap csv found adding to db"
		subprocess.call("""cat /data/tmp/dwcc-heatmap.csv | awk '!seen[$0]++' | sed -e 's/ //g' -e 's/[<>"^()@#&!$.,]//g' -e "s/'//g" -e '/^$/d' -e 's/[][]//g' -e 's/[-_]//g' -e 's/...$/000/' | sed -n 's/$/++/' >> /data/tmp/temp-dwcc-heatmap.csv """, shell=True)
		os.remove("/data/tmp/dwcc-heatmap.csv")
		os.rename("/data/tmp/temp-dwcc-heatmap.csv", "/data/tmp/dwcc-heatmap.csv")
		csv_heatmap = csv.reader(file(csvheatmap), delimiter='+')
		for rowheatmap in csv_heatmap:
			mycursor.execute('INSERT INTO dwccheatmapincoming (wlansa, wlanbssid, wlanradiosignaldbm, node, timestamp)' 'VALUES (?,?,?,?,?)', rowheatmap)



#This will remove the file after it is added to the db
		os.remove(csvheatmap)
		print "done with dbupdate for heatmap waiting for next run"
	else:
		print"csv heatmap not found will retry"
		

		
"""
def heatmapprep():
	mycursor.execute('''INSERT INTO dwccheatmapreporting (wlansa, timestamp, sigfromnode1)
SELECT wlansa,  timestamp, avg(wlanradiosignaldbm) as sigfromnode1 
FROM dwccheatmapincoming  
where node = 'node1' and addedtoreporting is null
GROUP BY wlansa, timestamp ;''')
	mycursor.execute('''UPDATE dwccheatmapincoming SET addedtoreporting = '1' WHERE addedtoreporting is null;''')
	
"""


def heatmapping():
	mycursor.execute('''SELECT max (timestamp) FROM dwccheatmapreporting GROUP BY timestamp limit 1;''')
	timestamptomap = mycursor.fetchone()
	timestamptomap = ''.join(c for c in timestamptomap if c not in string.punctuation)
	mycursor.execute("""select * from dwccheatmapreporting where timestamp = """+str(timestamptomap)+""";""")
	clientstomap  = mycursor.fetchall()
	
	mycursor.execute("""select * from dwccheatmapreporting where timestamp = """+str(timestamptomap)+""";""")
	clientstomap  = mycursor.fetchall()
	
	clientstomapwlansa = []
	clientstomapsigfromnode1 = []
	clientstomapsigfromnode2 = []
	clientstomapsigfromnode3 = []
	clientstomapsigfromnode4 = []
	clientstomapsigfromnode5 = []
	for i in clientstomap:
		clientstomapwlansa.append(str(i[1]))
		clientstomapsigfromnode1.append(i[3])
		clientstomapsigfromnode2.append(i[4])
		clientstomapsigfromnode3.append(i[5])
		clientstomapsigfromnode4.append(i[6])
		clientstomapsigfromnode5.append(i[7])
	print clientstomapwlansa, clientstomapsigfromnode1


"""
	
def taxonomyreporting():
#this is in testing
	mycursor.execute('''SELECT dwccincoming.wlansa, taxonomyassreass.vendormake
FROM dwccincoming
INNER JOIN taxonomyassreass ON  dwccincoming.wlanmgttagnumber =   taxonomyassreass.wlanmgttagnumber and dwccincoming.wlanmgttagoui = taxonomyassreass.wlanmgttagoui \
and dwccincoming.radiotapchannelflags2ghz = taxonomyassreass.radiotapchannelflags2ghz and dwccincoming.radiotapchannelflags5ghz = taxonomyassreass.radiotapchannelflags5ghz \
and dwccincoming.wlanmgtpowercapmax = taxonomyassreass.wlanmgtpowercapmax and dwccincoming.wlanmgtpowercapmin = taxonomyassreass.wlanmgtpowercapmin \
and dwccincoming.wlanmgthtampduparam = taxonomyassreass.wlanmgthtampduparam and dwccincoming.wlanmgtvhtcapabilitiestxstbc = taxonomyassreass.wlanmgtvhtcapabilitiestxstbc \
and dwccincoming.wlanmgtextcapb2 = taxonomyassreass.wlanmgtextcapb2 \
and dwccincoming.wlanmgtrsncapabilitiesmfpc = taxonomyassreass.wlanmgtrsncapabilitiesmfpc and dwccincoming.wlanmgtextcapb46 = taxonomyassreass.wlanmgtextcapb46 \
and dwccincoming.wlanmgtextcapb32 = taxonomyassreass.wlanmgtextcapb32 and dwccincoming.wlanmgtextcapb31 = taxonomyassreass.wlanmgtextcapb31 ;''')
	taxonomymatch  = mycursor.fetchall()
	print taxonomymatch
"""

start()
