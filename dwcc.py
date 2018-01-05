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
import socket
import subprocess
import os.path
import pysftp

#one day there will be support for more than one interface
interface = 'wlan1mon'
monitor_enable  = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
monitor_disable = 'iw dev wlan1mon del; ifconfig wlan1 up'
change_channel  = 'iw dev wlan1mon set channel %s'

#one day this will be changed to support 5ghz and 2ghz with two lists. Right now this works with a single daul band device
channels = [6, 48, 1, 11, 36, 40]

#info for sftp server
sshhost = '192.168.1.144'  #can be hostname or ip
sshuser = 'zach'           #make sure that key auth is working


hostname = socket.gethostname()

queue = multiprocessing.Queue()
incomingpath = '/data/incoming/' #This is the path where new pcaps will be placed

#This is the main function
def start():
	logging.basicConfig(filename='dwcc.log', format='%(levelname)s:%(message)s', level=logging.INFO)
	os.system(monitor_enable)
	stop_rotating = rotator(channels, change_channel)
	stop_uploading = uploader()
	try:sniffer(interface)
	except KeyboardInterrupt: sys.exit()
	finally:
		stop_rotating.set()
		stop_uploading.set()
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
	#subprocess.call('tcpdump -i wlan1mon -G 600 --packet-buffered -W 144 -e -s 512 type mgt -w /data/incoming/trace-%Y-%m-%d_%H.%M.%S.pcap', shell=True)
	print "sniffer would have started"
	time.sleep(100000)
#the above will rotate the pcap every 10 mins and keeps 24 hours worth
def uploader():
    def upload(stop):
        while not stop.is_set():
		try:
				for fname in os.listdir(incomingpath):
					if fname.endswith('.pcap'):
						with pysftp.Connection(host=sshhost, username=sshuser, private_key='~/.ssh/id_rsa') as sftp:
							with sftp.cd(incomingpath):
								sftp.put(incomingpath +fname)
					print "moved", fname
					os.remove(incomingpath +fname)
				else:
					print "no pcap found, will try again in 5 min"
					time.sleep(300) #seconds
		except KeyboardInterrupt: pass
    stop = multiprocessing.Event()
    multiprocessing.Process(target=upload, args=[stop]).start()
    return stop
start()
