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

incomingpath = '/data/incoming/' #This is the path where new pcaps will be placed
archivepath = '/data/archive/' #This is the path where pcaps what already have been checked will be placed
tmppath = '/data/tmp/' #this is the path for a tmp folder for dwcc to use
DB_FILE = 'dwcc.db'
def start():
#	dedup()
#	rowcount()
#	b19support()
#	mergecap()
#	tsharker()
#	dbupdater()
	dbmaker()
	dbupdater()
	
def dedup():
	cursor = mydb.cursor()
	stmt = """USE dwcc; DELETE FROM dwcc  WHERE id IN (SELECT * FROM (SELECT id FROM dwcc GROUP BY `wlan.sa` HAVING (COUNT(*) > 1)) AS A);"""
	cursor.execute(stmt)
	mydb.commit()
	mydb.close()

def rowcount():
	cursor = mydb.cursor()
	stmt = """SELECT COUNT(*)FROM dwcc;"""
	cursor.execute(stmt)
	numberofclient=cursor.fetchone()[0]
	print "Total number of clients found in the database = ", numberofclient 
#working on this
#def b19support():
#	cursor = mydb.cursor()
#	stmt = "SELECT COUNT(*) FROM dwcc WHERE `wlan_mgt.extcap.b19` = 1;"
#	cursor.execute(stmt)
#	b19supportcount=cursor.fetchone()[0]
#	print "Total number of clients found to support BSS Transition aka 802.11r aka FT = ", b19supportcount

#def mergecap():
#	subprocess.call('mergecap -w /nfs/$HOSTNAME/bigpcap.pcap /nfs/$HOSTNAME/archive/*.pcap', shell=True)
#	subprocess.call('rm -f /nfs/$HOSTNAME/archive/*.pcap', shell=True)

def tsharker():
 #This reads the pcaps, pull out the data, and places it into a csv
	def tshark(stop):
		while not stop.is_set():
	#checks for pcap files in incoming
			try:
				for fname in os.listdir(incomingpath):
					if fname.endswith('.pcap'):
						subprocess.call('cd ' + incomingpath + '; for filename in *.pcap; do tshark -r $filename -R "wlan.fc.type_subtype == 0x0" -2 -T fields -e wlan.sa -e wlan.bssid -e radiotap.channel.freq -e wlan_mgt.extcap.b19 -e wlan.fc.protected \
-e wlan_radio.channel -e wlan.fc.pwrmgt -e wlan_mgt.fixed.capabilities.radio_measurement -e wlan_mgt.ht.mcsset.txmaxss \
-e radiotap.channel.flags.ofdm -e radiotap.channel.flags.5ghz -e radiotap.channel.flags.2ghz -e wlan_mgt.fixed.capabilities.spec_man \
-e wlan_mgt.powercap.max -e wlan_mgt.powercap.min -e wlan_mgt.rsn.capabilities.mfpc -e wlan_mgt.extcap.b31 -e wlan_mgt.extcap.b32 -e wlan_mgt.extcap.b46 \
-e wlan_mgt.tag.number -e wlan_mgt.vht.capabilities.maxmpdulength -e wlan_mgt.vht.capabilities.supportedchanwidthset -e wlan_mgt.vht.capabilities.rxldpc \
-e wlan_mgt.vht.capabilities.short80 -e wlan_mgt.vht.capabilities.short160 -e wlan_mgt.vht.capabilities.txstbc -e wlan_mgt.vht.capabilities.subeamformer \
-e wlan_mgt.vht.capabilities.subeamformee -e wlan_mgt.vht.capabilities.beamformerants -e wlan_mgt.vht.capabilities.soundingdimensions -e wlan_mgt.vht.capabilities.mubeamformer \
-e wlan_mgt.vht.capabilities.mubeamformee -e wlan_mgt.tag.oui -E separator=+ >> ' + tmppath + 'dwcc.csv; mv $filename ' + archivepath + '/; done', shell=True)
				else:
					print "No pcap found waiting 5 mins to rerun"
					time.sleep(300)#seconds

			except KeyboardInterrupt: pass
	stop = multiprocessing.Event()
	multiprocessing.Process(target=tshark, args=[stop]).start()
	return stop

def dbupdater():
	conn = sqlite3.connect(DB_FILE)
	cursor = conn.cursor()
	def dbupdate(stop):
		while not stop.is_set():
			try:
				csvfile = '/data/tmp/dwcc.csv'
				if os.path.isfile(csvfile) and os.access(csvfile, os.R_OK):
					print "csv found"
					csv_data = csv.reader(file(csvfile), delimiter='+')
					for row in csv_data:
						conn.execute('INSERT INTO dwccincoming(wlansa, wlanbssid, radiotapchannelfreq, wlanmgtextcapb19, wlanfcprotected, \
wlanradiochannel, wlanfcpwrmgt, wlanmgtfixedcapabilitiesradiomeasurement, wlanmgthtmcssettxmaxss, \
radiotapchannelflagsofdm, radiotapchannelflags5ghz, radiotapchannelflags2ghz, wlanmgtfixedcapabilitiesspecman, \
wlanmgtpowercapmax, wlanmgtpowercapmin, wlanmgtrsncapabilitiesmfpc, wlanmgtextcapb31, wlanmgtextcapb32, wlanmgtextcapb46, \
wlanmgttagnumber, wlanmgtvhtcapabilitiesmaxmpdulength, wlanmgtvhtcapabilitiessupportedchanwidthset, wlanmgtvhtcapabilitiesrxldpc, \
wlanmgtvhtcapabilitiesshort80, wlanmgtvhtcapabilitiesshort160, wlanmgtvhtcapabilitiestxstbc, wlanmgtvhtcapabilitiessubeamformer, \
wlanmgtvhtcapabilitiessubeamformee, wlanmgtvhtcapabilitiesbeamformerants, wlanmgtvhtcapabilitiessoundingdimensions, wlanmgtvhtcapabilitiesmubeamformer, \
wlanmgtvhtcapabilitiesmubeamformee, wlanmgttagoui)' \
'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', row)
					conn.commit()
					conn.close()
					print "done with dbupdate waiting 4 mins for next run"
					time.sleep(240)#seconds
				else:
					print"csv not found will retry in 4 mins"
					print csvfile
					time.sleep(240)#seconds
			except KeyboardInterrupt: pass
	stop = multiprocessing.Event()
	multiprocessing.Process(target=dbupdate, args=[stop]).start()
	return stop

def dbmaker():
	newfile = False
	if not os.path.exists(DB_FILE): 
		print "creating .db"
		newfile = True
	conn = sqlite3.connect(DB_FILE)
	cursor = conn.cursor()
	if newfile == True:
		conn.execute('''CREATE TABLE dwccincoming
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
	   wlanmgttagoui char(50));''')
		conn.execute('''CREATE TABLE dwccreporting
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
	   wlanmgtfixedcapabilitiesspec_man char(50),
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
	   clientvendor char(50),
	   clientwifichipvendor char(50));''')
	conn.commit()
	conn.close()

start()

#will be added at a later time
#radiotap.antenna
#wlan.ssid
