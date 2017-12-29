#Need to cleanup the ones we are not using
import sys
import os
import logging
import traceback
import random
import time
import datetime
import multiprocessing
import Queue
import MySQLdb
import pcapy
import dpkt
import socket
import subprocess
import csv
import os.path

# linux
#one day there will be support for more than one interface
interface = 'wlan1mon'
monitor_enable  = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
monitor_disable = 'iw dev wlan1mon del; ifconfig wlan1 up'
change_channel  = 'iw dev wlan1mon set channel %s'

#one day this will be changed to support 5ghz and 2ghz with two lists. Right now this works with a single daul band device
channels = [6, 48, 1, 11, 36, 40]

#mysql support coming soon
mydb = MySQLdb.connect(host='localhost',
    user='dwcc',
    passwd='dwcc',
    db='dwcc')


hostname = socket.gethostname()

queue = multiprocessing.Queue()


#This is the main fuction
def start():
	logging.basicConfig(filename='dwcc.log', format='%(levelname)s:%(message)s', level=logging.INFO)
	os.system(monitor_enable)
	stop_rotating = rotator(channels, change_channel)
	stop_tsharking = tsharker()
	stop_dbupdateing = dbupdater()
	try:sniffer(interface)
	except KeyboardInterrupt: sys.exit()
	finally:
		stop_rotating.set()
		stop_tsharking.set()
		stop_dbupdateing.set()
		os.system(monitor_disable)

#This will change the channels every 1 sec to scan all in the range. One day there will be support for more than one rotator to support 2.4ghz and 5ghz.		
def rotator(channels, change_channel):
    def rotate(stop):
        while not stop.is_set():
            try:
                channel = str(random.choice(channels))
                logging.info('Changing to channel ' + channel)
                os.system(change_channel % channel)
                time.sleep(1) # seconds
            except KeyboardInterrupt: pass
    stop = multiprocessing.Event()
    multiprocessing.Process(target=rotate, args=[stop]).start()
    return stop

#this is the caputre fuction, It will only caputre the mgt frames.
def sniffer(interface):
	subprocess.call('tcpdump -i wlan1mon -G 600 --packet-buffered -W 144 -e -s 512 type mgt -w ./incoming/trace-%Y-%m-%d_%H.%M.%S.pcap', shell=True)
	#This fuction does not stop right when you exit program
#the above will rotate the pcap every 10 mins and keeps 24 hours worth
def tsharker():
 #This reads the pcaps, pull out the data, and places it into a csv
	def tshark(stop):
		while not stop.is_set():
	#checks for pcap files in incoming
			try:
				for fname in os.listdir('./incoming'):
					if fname.endswith('.pcap'):
						subprocess.call('cd ./incoming; for filename in *.pcap; do tshark -r $filename -R "wlan.fc.type_subtype == 0x0" -2 -T fields -e wlan.sa -e wlan.bssid -e radiotap.channel.freq -e wlan_mgt.extcap.b19 -e wlan.fc.protected \
-e wlan_radio.channel -e wlan.fc.pwrmgt -e wlan_mgt.fixed.capabilities.radio_measurement -e wlan_mgt.ht.mcsset.txmaxss \
-e radiotap.channel.flags.ofdm -e radiotap.channel.flags.5ghz -e radiotap.channel.flags.2ghz -e wlan_mgt.fixed.capabilities.spec_man \
-e wlan_mgt.powercap.max -e wlan_mgt.powercap.min -e wlan_mgt.rsn.capabilities.mfpc -e wlan_mgt.extcap.b31 -e wlan_mgt.extcap.b32 -e wlan_mgt.extcap.b46 \
-e wlan_mgt.tag.number -e wlan_mgt.vht.capabilities.maxmpdulength -e wlan_mgt.vht.capabilities.supportedchanwidthset -e wlan_mgt.vht.capabilities.rxldpc \
-e wlan_mgt.vht.capabilities.short80 -e wlan_mgt.vht.capabilities.short160 -e wlan_mgt.vht.capabilities.txstbc -e wlan_mgt.vht.capabilities.subeamformer \
-e wlan_mgt.vht.capabilities.subeamformee -e wlan_mgt.vht.capabilities.beamformerants -e wlan_mgt.vht.capabilities.soundingdimensions -e wlan_mgt.vht.capabilities.mubeamformer \
-e wlan_mgt.vht.capabilities.mubeamformee -e wlan_mgt.tag.oui -E separator=+ >> ../tmp/dwcc.csv; mv $filename ../archive/; done', shell=True)
				else:
					print "No pcap found waiting 5 mins to rerun"
					time.sleep(300)#seconds

			except KeyboardInterrupt: pass
	stop = multiprocessing.Event()
	multiprocessing.Process(target=tshark, args=[stop]).start()
	return stop
#this below needs to be tested

#This is the DB section
def dbupdater():
#checking for the table
			cursor = mydb.cursor()
			stmt = "SHOW TABLES LIKE 'dwcc'"
			cursor.execute(stmt)
			result = cursor.fetchone()
			if result:
			#If table is found thing start the loop to read csv into the table
				print "there is a table named dwcc"
				def dbupdate(stop):
					while not stop.is_set():
						try:
							csvcheck = './tmp/dwcc.csv'
							if os.path.isfile(csvcheck) and os.access(csvcheck, os.R_OK):
								print "csv found"
								csv_data = csv.reader(file('./tmp/dwcc.csv'), delimiter='+')
								for row in csv_data:
									cursor.execute('INSERT INTO dwcc(`wlan.sa`, `wlan.bssid`, `radiotap.channel.freq`, `wlan_mgt.extcap.b19`, `wlan.fc.protected`, \
`wlan_radio.channel`, `wlan.fc.pwrmgt`, `wlan_mgt.fixed.capabilities.radio_measurement`, `wlan_mgt.ht.mcsset.txmaxss`, \
`radiotap.channel.flags.ofdm`, `radiotap.channel.flags.5ghz`, `radiotap.channel.flags.2ghz`, `wlan_mgt.fixed.capabilities.spec_man`, \
`wlan_mgt.powercap.max`, `wlan_mgt.powercap.min`, `wlan_mgt.rsn.capabilities.mfpc`, `wlan_mgt.extcap.b31`, `wlan_mgt.extcap.b32`, `wlan_mgt.extcap.b46`, \
`wlan_mgt.tag.number`, `wlan_mgt.vht.capabilities.maxmpdulength`, `wlan_mgt.vht.capabilities.supportedchanwidthset`, `wlan_mgt.vht.capabilities.rxldpc`, \
`wlan_mgt.vht.capabilities.short80`, `wlan_mgt.vht.capabilities.short160`, `wlan_mgt.vht.capabilities.txstbc`, `wlan_mgt.vht.capabilities.subeamformer`, \
`wlan_mgt.vht.capabilities.subeamformee`, `wlan_mgt.vht.capabilities.beamformerants`, `wlan_mgt.vht.capabilities.soundingdimensions`, `wlan_mgt.vht.capabilities.mubeamformer`, \
`wlan_mgt.vht.capabilities.mubeamformee`, `wlan_mgt.tag.oui`)' \
'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', row)
									mydb.commit()
								os.remove('./tmp/dwcc.csv')	
								print "done with dbupdate waiting 4 mins for next run"
								time.sleep(240)#seconds
							else:
								print"csv not found will retry in 4 mins"
								time.sleep(240)#seconds
						except KeyboardInterrupt: pass
				stop = multiprocessing.Event()
				multiprocessing.Process(target=dbupdate, args=[stop]).start()
				return stop
			else:
			#if table is no found then make the table
				print "there are no tables named dwcc, making it"
				cursor.execute('USE dwcc; CREATE TABLE dwcc (id INT NOT NULL AUTO_INCREMENT, `wlan.sa` VARCHAR(50), `wlan.bssid` VARCHAR(50), `radiotap.channel.freq` VARCHAR(50), `wlan_mgt.extcap.b19` VARCHAR(50), `wlan.fc.protected` VARCHAR(50), \
`wlan_radio.channel` VARCHAR(50), `wlan.fc.pwrmgt` VARCHAR(50), `wlan_mgt.fixed.capabilities.radio_measurement` VARCHAR(50), `wlan_mgt.ht.mcsset.txmaxss` VARCHAR(50), \
`radiotap.channel.flags.ofdm` VARCHAR(50), `radiotap.channel.flags.5ghz` VARCHAR(50), `radiotap.channel.flags.2ghz` VARCHAR(50), `wlan_mgt.fixed.capabilities.spec_man` VARCHAR(50), \
`wlan_mgt.powercap.max` VARCHAR(50), `wlan_mgt.powercap.min` VARCHAR(50), `wlan_mgt.rsn.capabilities.mfpc` VARCHAR(50), `wlan_mgt.extcap.b31` VARCHAR(50), `wlan_mgt.extcap.b32` VARCHAR(50), `wlan_mgt.extcap.b46` VARCHAR(50), \
`wlan_mgt.tag.number` VARCHAR(50), `wlan_mgt.vht.capabilities.maxmpdulength` VARCHAR(50), `wlan_mgt.vht.capabilities.supportedchanwidthset` VARCHAR(50), `wlan_mgt.vht.capabilities.rxldpc` VARCHAR(50), \
`wlan_mgt.vht.capabilities.short80` VARCHAR(50), `wlan_mgt.vht.capabilities.short160` VARCHAR(50), `wlan_mgt.vht.capabilities.txstbc` VARCHAR(50), `wlan_mgt.vht.capabilities.subeamformer` VARCHAR(50), \
`wlan_mgt.vht.capabilities.subeamformee` VARCHAR(50), `wlan_mgt.vht.capabilities.beamformerants` VARCHAR(50), `wlan_mgt.vht.capabilities.soundingdimensions` VARCHAR(50), `wlan_mgt.vht.capabilities.mubeamformer` VARCHAR(50), \
`wlan_mgt.vht.capabilities.mubeamformee` VARCHAR(50), `wlan_mgt.tag.oui` VARCHAR(50), PRIMARY KEY ( id ));')


#	#close the connection to the database.
	#	mydb.commit()
	#	mydb.close()
#
#	db.close()


start()
