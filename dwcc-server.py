#!/usr/bin/python
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
from manuf import manuf
import string

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
			dbconverter()
			charting()
##			mergecap()
			macaddressconverter()
			time.sleep(300)#seconds
		except KeyboardInterrupt: sys.exit()

def preflightcheck():
	if not os.path.exists(incomingpath):
		os.makedirs(incomingpath)
	if not os.path.exists(archivepath):
		os.makedirs(archivepath)		
	if not os.path.exists(tmppath):
		os.makedirs(tmppath)	

#this will take a look at the mac address of the trasmitter and 
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
	cursor.execute('SELECT wlansaconverted, count(wlansaconverted) FROM dwccincoming GROUP BY wlansaconverted ORDER BY count(wlansaconverted) DESC;')
	devicemaker=cursor.fetchall()
	cursor.execute('SELECT wlanradiochannel, count(wlanradiochannel) FROM dwccincoming GROUP BY wlanradiochannel ORDER BY count(wlanradiochannel) DESC;')
	channelgroup=cursor.fetchall()
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb46 = 1;')
	wnmsupport=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessoundingdimensions = 0;')
	soundingdimensions0=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessoundingdimensions = 1;')
	soundingdimensions1=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessoundingdimensions = 3;')
	soundingdimensions3=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesmubeamformee = 1;')
	wlanmgtvhtcapabilitiesmubeamformee=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesmubeamformer = 1;')
	wlanmgtvhtcapabilitiesmubeamformer=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessubeamformee = 1;')
	wlanmgtvhtcapabilitiessubeamformee=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessubeamformer = 1;')
	wlanmgtvhtcapabilitiessubeamformer=cursor.fetchone()[0]
	cursor.execute('SELECT wlanmgtpowercapmax, count(wlanmgtpowercapmax) FROM dwccincoming GROUP BY wlanmgtpowercapmax ORDER BY count(wlanmgtpowercapmax) DESC;')
	wlanmgtpowercapmax=cursor.fetchall()
	cursor.execute('SELECT wlanmgtpowercapmin, count(wlanmgtpowercapmin) FROM dwccincoming GROUP BY wlanmgtpowercapmin ORDER BY count(wlanmgtpowercapmin) DESC;')
	wlanmgtpowercapmin=cursor.fetchall()
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtfixedcapabilitiesspecman = 1;')
	wlanmgtfixedcapabilitiesspecman=cursor.fetchone()[0]
	cursor.execute('SELECT wlanmgtvhtcapabilitiesmaxmpdulength, count(wlanmgtvhtcapabilitiesmaxmpdulength) FROM dwccincoming GROUP BY wlanmgtvhtcapabilitiesmaxmpdulength ORDER BY count(wlanmgtvhtcapabilitiesmaxmpdulength) DESC;')
	wlanmgtvhtcapabilitiesmaxmpdulength=cursor.fetchall()
	
	wlanmgtvhtcapabilitiesmaxmpdulength
	print "Total number of clients found to support Sounding Dimensions of 1 = ", soundingdimensions0
	print "Total number of clients found to support Sounding Dimensions of 0 = ", soundingdimensions1
	print "Total number of clients found to support Sounding Dimensions of 3 = ", soundingdimensions3
	print "Total number of clients found to support BSS Transition aka 802.11r aka FT = ", b19supportcount
	print "Total number of clients found to support 80mhz channel in 5ghz = ", n80mhzsupportcount
	print "Total number of clients found to support 160mhz channel in 5ghz = ", n160mhzsupportcount
	print "Total number of 5 ghz clients found= ", n5ghzclientcount
	print "Total number of 2 ghz clients found= ", n2ghzclientcount
	print "Total number of clients that support 802.11w= ", n80211wsupport
	print "Total number of clients that support interworking this is reated to 802.11u= ", n80211usupport
	print "Total number of clients that support QOS map= ", qosmapsupport
	print "Total number of clients that support wnm notification= ", wnmsupport
	print "Total number of clients that support can recive frames from mu-mino AP= ", wlanmgtvhtcapabilitiesmubeamformee
	print "Total number of clients that support can send frames from mu-mino AP= ", wlanmgtvhtcapabilitiesmubeamformer
	print "Total number of clients that support can recive frames from single user beamforming AP= ", wlanmgtvhtcapabilitiessubeamformee
	print "Total number of clients that support can send frames from single user beamforming AP= ", wlanmgtvhtcapabilitiessubeamformer
	print devicemaker
	print channelgroup
	print "power max", wlanmgtpowercapmax
	print "power min", wlanmgtpowercapmin
	print "Total number of clients that support 802.11h/dfs channels. This will only show on 5ghz clients", wlanmgtfixedcapabilitiesspecman
	print "Maximum MPDU Length in bytes", wlanmgtvhtcapabilitiesmaxmpdulength

def dbconverter():
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessoundingdimensions = '1' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000001';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessoundingdimensions = '0' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000000';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessoundingdimensions = '3' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000002';")
	cursor.execute("UPDATE dwccincoming SET wlansaconverted = 'vendornotfound' WHERE wlansaconverted  = 'None';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiesmaxmpdulength = '11454' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000002';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiesmaxmpdulength = '7991' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000001';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiesmaxmpdulength = '3895' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000000';")
	conn.commit()

#def mergecap():
#	subprocess.call('mergecap -w /nfs/$HOSTNAME/bigpcap.pcap /nfs/$HOSTNAME/archive/*.pcap', shell=True)
#	subprocess.call('rm -f /nfs/$HOSTNAME/archive/*.pcap', shell=True)


def tsharker():
 #This reads the pcaps, pull out the data, and places it into a csv
	#checks for pcap files in incoming
	
	for fname in os.listdir(incomingpath):
					if fname.endswith('.pcap'):
						pcapfile = incomingpath +fname
						subprocess.call('tshark -r ' + pcapfile + '  -R "wlan.fc.type_subtype == 0x0 or wlan.fc.type_subtype == 0x2" -2 -T fields -e wlan.sa -e wlan.bssid -e radiotap.channel.freq -e wlan_mgt.extcap.b19 -e wlan.fc.protected \
-e wlan_radio.channel -e wlan.fc.pwrmgt -e wlan_mgt.fixed.capabilities.radio_measurement -e wlan_mgt.ht.mcsset.txmaxss \
-e radiotap.channel.flags.ofdm -e radiotap.channel.flags.5ghz -e radiotap.channel.flags.2ghz -e wlan_mgt.fixed.capabilities.spec_man \
-e wlan_mgt.powercap.max -e wlan_mgt.powercap.min -e wlan_mgt.rsn.capabilities.mfpc -e wlan_mgt.extcap.b31 -e wlan_mgt.extcap.b32 -e wlan_mgt.extcap.b46 \
-e wlan_mgt.tag.number -e wlan_mgt.vht.capabilities.maxmpdulength -e wlan_mgt.vht.capabilities.supportedchanwidthset -e wlan_mgt.vht.capabilities.rxldpc \
-e wlan_mgt.vht.capabilities.short80 -e wlan_mgt.vht.capabilities.short160 -e wlan_mgt.vht.capabilities.txstbc -e wlan_mgt.vht.capabilities.subeamformer \
-e wlan_mgt.vht.capabilities.subeamformee -e wlan_mgt.vht.capabilities.beamformerants -e wlan_mgt.vht.capabilities.soundingdimensions -e wlan_mgt.vht.capabilities.mubeamformer \
-e wlan_mgt.vht.capabilities.mubeamformee -e wlan_mgt.tag.oui -e wlan_mgt.fixed.capabilities.ess -e radiotap.antenna -E separator=+ >> ' + tmppath + 'dwcc.csv', shell=True)
			#subprocess.call("""sed -i -e 's/ /-/g' -e 's/[<>"^()]//g' /data/tmp/dwcc.csv""", shell=True)
						#this below will move the pcap into the archive folder
						os.rename(incomingpath +fname, archivepath +fname)
						print "pcap found and tshark has ran"
					else:
						print "No pcap found waiting 5 mins to rerun"

def macaddressconverter():
	p = manuf.MacParser(update=True)
	cursor.execute("""SELECT wlansa from dwccincoming WHERE wlansaconverted IS NULL OR wlansaconverted = '' limit 1;""")
	mactochange = cursor.fetchone()
	
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
		cursor.execute("UPDATE dwccincoming SET wlansaconverted = "+ `changedmacstr` +" WHERE wlansa  = "+ `mactochangestr` +"   ;")
#				print changedmac
#				print mactochange
		conn.commit()
		macaddressconverter()
#			cursor.execute("""SELECT COUNT(wlansa) from dwccincoming WHERE wlansaconverted IS NULL OR wlansaconverted = ''""")
#			nullrowleft = cursor.fetchone()[0]
#			print "Total rows left to be converted = ", nullrowleft
#This will take the CSV and place it into the db
def dbupdater():
	csvfile = '/data/tmp/dwcc.csv'
	#this will check for the CSV file, If it is found then import it into the database. If no CSV is found then it move on
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
#This will remove the file after it is added to the db
		os.remove(csvfile)
		print "done with dbupdate waiting for next run"
	else:
		print"csv not found will retry"

#This check for the database and if it is not found, it will make it.
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
wlanmgtssid char(100),
wlansaconverted char(200));''')

	conn.commit()

start()
## add support for 
#wlan.extcap.b4 == 0
#wlan.extcap.b3  this is 802.11p
#wlan.extcap.b2 this is realted to 802.11y
# wlan.extcap.b1 this is On-demand beacon realted to 802.11p
# wlan.extcap.b6
#wlan.extcap.b8 == 0
#wlan.extcap.b9 == 0
#wlan.extcap.b10 == 0
#wlan.extcap.b11 == 0
#wlan.extcap.b12 == 0
#wlan.extcap.b13 == 0
#wlan.extcap.b14 == 0
#wlan.extcap.b15 == 0
#wlan.extcap.b16 == 0
#wlan.extcap.b17 == 0
#wlan.extcap.b18 == 0
#wlan.extcap.b20 == 0
#wlan.extcap.b21 == 0
#wlan.extcap.b22 == 0
#wlan.extcap.b23 == 0
#wlan.extcap.b24 == 0
#wlan.extcap.b25 == 0
#wlan.extcap.b26 == 0
#wlan.extcap.b27 == 0
#wlan.extcap.b28 == 0
#wlan.extcap.b29 == 0
#wlan.extcap.b30 == 0
#wlan.extcap.b33 == 0
#wlan.extcap.b34 == 0
#wlan.extcap.b35 == 0
#wlan.extcap.b36 == 0
#wlan.extcap.b37 == 0
#wlan.extcap.b38 == 0
#wlan.extcap.b39 == 0
#wlan.extcap.b40 == 0
#wlan.extcap.serv_int_granularity
#wlan.extcap.b44 == 0
#wlan.extcap.b45 == 0
#wlan.extcap.b46 == 0
#wlan.extcap.b47 == 0
#wlan.extcap.b48 
#wlan.extcap.b61
#wlan.extcap.b62
#wlan.extcap.b63
#wlan.vht.capabilities.rxstbc == 0x1 realted to Spatial Stream Supported 
#wlan.vht.mcsset.rxmcsmap.ss2 realted to Spatial Stream Supported
#wlan.vht.mcsset.rxmcsmap.ss1 realted to Spatial Stream Supported
#wlan.vht.mcsset.rxmcsmap.ss3 realted to Spatial Stream Supported
#wlan.vht.mcsset.rxmcsmap.ss4 realted to Spatial Stream Supported
#wlan.vht.mcsset.txmcsmap.ss1 realted to Spatial Stream Supported
#wlan.vht.mcsset.txmcsmap.ss2 realted to Spatial Stream Supported
#wlan.vht.mcsset.txmcsmap.ss1 realted to Spatial Stream Supported
#wlan.vht.mcsset.txmcsmap.ss2 realted to Spatial Stream Supported
#wlan.vht.mcsset.txmcsmap.ss3 realted to Spatial Stream Supported
#wlan.vht.mcsset.txmcsmap.ss4 realted to Spatial Stream Supported