import sys
import os
import logging
import sqlite3
import subprocess
import multiprocessing
import time
import datetime
import csv
import os.path

#This change the below to reflect your sysrem
incomingpath = '/data/incoming/' #This is the path where new pcaps will be placed
archivepath = '/data/archive/' #This is the path where pcaps what already have been checked will be placed
tmppath = '/data/tmp/' #this is the path for a tmp folder for dwcc to use
DB_FILE = 'dwcc.db'
#you may change the path but please dont change the filename
csvfile = '/data/tmp/dwcc.csv'

#here is the setup info for the sqlite db
conn = sqlite3.connect(DB_FILE)
conn.text_factory = str
cursor = conn.cursor()

#this is the main fuction 
def start():
	preflightcheck()
	dbmaker()
	while True:
		try:
			tsharker()
			dbupdater()
			dedup()
			rowcount()
			charting()
#			mergecap()
			dbconverter()
			time.sleep(300)#seconds
		except KeyboardInterrupt: sys.exit()

def preflightcheck():
	if not os.path.exists(incomingpath):
		os.makedirs(incomingpath)
	if not os.path.exists(archivepath):
		os.makedirs(archivepath)		
	if not os.path.exists(tmppath):
		os.makedirs(tmppath)	

def dedup():
	cursor.execute('DELETE FROM dwccincoming WHERE ID NOT IN (SELECT min(ID) FROM dwccincoming GROUP BY wlansa);')
	conn.commit()
	print "finish dedup"

def rowcount():
	cursor.execute('SELECT COUNT(*)FROM dwccincoming;')
	numberofclient=cursor.fetchone()[0]
	print "Total number of clients found in the database = ", numberofclient 
#working on this
def charting():
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb19 = 1;')
	b19supportcount=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesshort80 = 1;')
	n80mhzsupportcount=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesshort160 = 1;')
	n160mhzsupportcount=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE radiotapchannelflags5ghz = 1;')
	n5ghzclientcount=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE radiotapchannelflags2ghz = 1;')
	n2ghzclientcount=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtrsncapabilitiesmfpc = 1;')
	n80211wsupport=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb31 = 1;')
	n80211usupport=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb32 = 1;')
	qosmapsupport=cursor.fetchone()[0]
	print "Total number of clients found to support BSS Transition aka 802.11r aka FT = ", b19supportcount
	print "Total number of clients found to support 80mhz channel in 5ghz = ", n80mhzsupportcount
	print "Total number of clients found to support 160mhz channel in 5ghz = ", n160mhzsupportcount
	print "Total number of 5 ghz clients found= ", n5ghzclientcount
	print "Total number of 2 ghz clients found= ", n2ghzclientcount
	print "Total number of clients that support 802.11w= ", n80211wsupport
	print "Total number of clients that support interworking this is reated to 802.11u= ", n80211usupport
	print "Total number of clients that support QOS map= ", qosmapsupport


def dbconverter():
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessoundingdimensions = '1' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000001';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessoundingdimensions = '0' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000000';")
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessoundingdimensions = 0;')
	soundingdimensions0=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessoundingdimensions = 1;')
	soundingdimensions1=cursor.fetchone()[0]
	print "Total number of clients found to support Sounding Dimensions of 1 = ", soundingdimensions0
	print "Total number of clients found to support Sounding Dimensions of 0 = ", soundingdimensions1
	conn.commit()

#def mergecap():
#	subprocess.call('mergecap -w /nfs/$HOSTNAME/bigpcap.pcap /nfs/$HOSTNAME/archive/*.pcap', shell=True)
#	subprocess.call('rm -f /nfs/$HOSTNAME/archive/*.pcap', shell=True)

#add support for https://github.com/coolbho3k/manuf

def tsharker():
 #This reads the pcaps, pull out the data, and places it into a csv
	#checks for pcap files in incoming
	for fname in os.listdir(incomingpath):
		if fname.endswith('.pcap'):
			subprocess.call('cd ' + incomingpath + '; for filename in *.pcap; do tshark -r $filename  -R "wlan.fc.type_subtype == 0x0 or wlan.fc.type_subtype == 0x3" -2 -T fields -e wlan.sa -e wlan.bssid -e radiotap.channel.freq -e wlan_mgt.extcap.b19 -e wlan.fc.protected \
-e wlan_radio.channel -e wlan.fc.pwrmgt -e wlan_mgt.fixed.capabilities.radio_measurement -e wlan_mgt.ht.mcsset.txmaxss \
-e radiotap.channel.flags.ofdm -e radiotap.channel.flags.5ghz -e radiotap.channel.flags.2ghz -e wlan_mgt.fixed.capabilities.spec_man \
-e wlan_mgt.powercap.max -e wlan_mgt.powercap.min -e wlan_mgt.rsn.capabilities.mfpc -e wlan_mgt.extcap.b31 -e wlan_mgt.extcap.b32 -e wlan_mgt.extcap.b46 \
-e wlan_mgt.tag.number -e wlan_mgt.vht.capabilities.maxmpdulength -e wlan_mgt.vht.capabilities.supportedchanwidthset -e wlan_mgt.vht.capabilities.rxldpc \
-e wlan_mgt.vht.capabilities.short80 -e wlan_mgt.vht.capabilities.short160 -e wlan_mgt.vht.capabilities.txstbc -e wlan_mgt.vht.capabilities.subeamformer \
-e wlan_mgt.vht.capabilities.subeamformee -e wlan_mgt.vht.capabilities.beamformerants -e wlan_mgt.vht.capabilities.soundingdimensions -e wlan_mgt.vht.capabilities.mubeamformer \
-e wlan_mgt.vht.capabilities.mubeamformee -e wlan_mgt.tag.oui -e wlan_mgt.fixed.capabilities.ess -e radiotap.antenna -E separator=+ >> ' + tmppath + 'dwcc.csv && mv $filename ' + archivepath + '/; done', shell=True)
			#subprocess.call("""sed -i -e 's/ /-/g' -e 's/[<>"^()]//g' /data/tmp/dwcc.csv""", shell=True)
			print "pcap found and tshark has ran"
		else:
			print "No pcap found waiting 5 mins to rerun"

			
def dbupdater():
	
	csvfile = '/data/tmp/dwcc.csv'
	if os.path.isfile(csvfile) and os.access(csvfile, os.R_OK):
		print "csv found added to db"
		csv_data = csv.reader(file(csvfile), delimiter='+')
		for row in csv_data:
			conn.execute('INSERT INTO dwccincoming(wlansa, wlanbssid, radiotapchannelfreq, wlanmgtextcapb19, wlanfcprotected, \
wlanradiochannel, wlanfcpwrmgt, wlanmgtfixedcapabilitiesradiomeasurement, wlanmgthtmcssettxmaxss, \
radiotapchannelflagsofdm, radiotapchannelflags5ghz, radiotapchannelflags2ghz, wlanmgtfixedcapabilitiesspecman, \
wlanmgtpowercapmax, wlanmgtpowercapmin, wlanmgtrsncapabilitiesmfpc, wlanmgtextcapb31, wlanmgtextcapb32, wlanmgtextcapb46, \
wlanmgttagnumber, wlanmgtvhtcapabilitiesmaxmpdulength, wlanmgtvhtcapabilitiessupportedchanwidthset, wlanmgtvhtcapabilitiesrxldpc, \
wlanmgtvhtcapabilitiesshort80, wlanmgtvhtcapabilitiesshort160, wlanmgtvhtcapabilitiestxstbc, wlanmgtvhtcapabilitiessubeamformer, \
wlanmgtvhtcapabilitiessubeamformee, wlanmgtvhtcapabilitiesbeamformerants, wlanmgtvhtcapabilitiessoundingdimensions, wlanmgtvhtcapabilitiesmubeamformer, \
wlanmgtvhtcapabilitiesmubeamformee, wlanmgttagoui,  wlanmgtfixedcapabilitiesess, radiotapantenna)' \
'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', row)
		conn.commit()
		os.remove(csvfile)
		print "done with dbupdate waiting for next run"
	else:
		print"csv not found will retry"

def dbmaker():

	conn = sqlite3.connect(DB_FILE)
	cursor = conn.cursor()
	cursor.execute('''CREATE TABLE if not exists dwccincoming
(ID INTEGER PRIMARY KEY autoincrement NOT NULL,
wlansa char(50),
wlanbssid char(50),
radiotapchannelfreq char(50),
wlanmgtextcapb19 char(50),
wlanfcprotected char(50),
wlanradiochannel char(50),
wlanfcpwrmgt char(50),
wlanmgtfixedcapabilitiesradiomeasurement char(50),
wlanmgthtmcssettxmaxss char(50),
radiotapchannelflagsofdm char(50),
radiotapchannelflags5ghz char(50),
radiotapchannelflags2ghz char(50),
wlanmgtfixedcapabilitiesspecman char(50),
wlanmgtpowercapmax char(50),
wlanmgtpowercapmin char(50),
wlanmgtrsncapabilitiesmfpc char(50),
wlanmgtextcapb31 char(50),
wlanmgtextcapb32 char(50),
wlanmgtextcapb46 char(50),
wlanmgttagnumber char(50),
wlanmgtvhtcapabilitiesmaxmpdulength char(50),
wlanmgtvhtcapabilitiessupportedchanwidthset char(50),
wlanmgtvhtcapabilitiesrxldpc char(50),
wlanmgtvhtcapabilitiesshort80 char(50),
wlanmgtvhtcapabilitiesshort160 char(50),
wlanmgtvhtcapabilitiestxstbc char(50),
wlanmgtvhtcapabilitiessubeamformer char(50),
wlanmgtvhtcapabilitiessubeamformee char(50),
wlanmgtvhtcapabilitiesbeamformerants char(50),
wlanmgtvhtcapabilitiessoundingdimensions char(50),
wlanmgtvhtcapabilitiesmubeamformer char(50),
wlanmgtvhtcapabilitiesmubeamformee char(50),
wlanmgttagoui char(50),
wlanmgtfixedcapabilitiesess char(50),
radiotapantenna char(50), 
wlanmgtssid char(100));''')

	conn.commit()

start()