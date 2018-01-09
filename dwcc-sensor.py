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
from subprocess import Popen


#1 is enabled, 0 is disabled
interface3enable = '1'
interface3 = 'wlan0mon'
monitor_enable3  = 'ifconfig wlan0 down; iw dev wlan0 interface add wlan0mon type monitor; ifconfig wlan0mon down; iw dev wlan0mon set type monitor; ifconfig wlan0mon up'
monitor_disable3 = 'iw dev wlan0mon del; ifconfig wlan0 up'
change_channel3  = 'iw dev wlan0mon set channel %s'
channels3 = [6, 48, 1, 11, 36, 40, 44, 10 ] #use the linux command "iwlist channel" to get a list of every channel your devices supports)



#At this more than interface has not been tested
#1 is enabled, 0 is disabled
interface1enable = '1'
interface1 = 'wlan1mon'
monitor_enable1  = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
monitor_disable1 = 'iw dev wlan1mon del; ifconfig wlan1 up'
change_channel1  = 'iw dev wlan1mon set channel %s'
channels1 = [6, 48, 1, 11, 36, 40] #use the linux command "iwlist channel" to get a list of every channel your devices supports)

#At this more than interface has not been tested
#1 is enabled, 0 is disabled
interface2enable = '1'
interface2 = 'wlan2mon'
monitor_enable2 = 'ifconfig wlan2 down; iw dev wlan2 interface add wlan2mon type monitor; ifconfig wlan2mon down; iw dev wlan2mon set type monitor; ifconfig wlan2mon up'
monitor_disable2 = 'iw dev wlan2mon del; ifconfig wlan2 up'
change_channel2  = 'iw dev wlan2mon set channel %s'
channels2 = [6, 48, 1, 11, 36, 40] #use the linux command "iwlist channel" to get a list of every channel your devices supports)

#1 is enabled, 0 is disabled
#interface3enable = '1'
#interface3 = 'wlan3mon'
#monitor_enable3  = 'ifconfig wlan3 down; iw dev wlan3 interface add wlan3mon type monitor; ifconfig wlan3mon down; iw dev wlan3mon set type monitor; ifconfig wlan3mon up'
#monitor_disable3 = 'iw dev wlan3mon del; ifconfig wlan3 up'
#change_channel3  = 'iw dev wlan3mon set channel %s'
#channels1 = [6, 48, 1, 11, 36, 40, 44, 10 ] #use the linux command "iwlist channel" to get a list of every channel your devices supports)

#info for sftp server
sshhost = '192.168.1.144'  #can be hostname or ip
sshuser = 'zach'           #make sure that key auth is working

hostname = socket.gethostname()

queue = multiprocessing.Queue()
incomingpath = '/data/incoming/' #This is the path where new pcaps will be placed

#This is the main function
def start():
	logging.basicConfig(filename='dwcc.log', format='%(levelname)s:%(message)s', level=logging.INFO)
	if interface1enable == '1':
		os.system(monitor_enable1)
		print "starting wlan1"
	if interface2enable == '1':
		os.system(monitor_enable2)
		print "starting wlan2"
	if interface3enable == '1':
		os.system(monitor_enable3)
		print "starting wlan3"
	stop_rotating = rotator()
#	stop_uploading = uploader()
	try:sniffer()
	except KeyboardInterrupt: sys.exit()
	finally:
		print "Please wait for everything to stop"
		stop_rotating.set()
#		stop_uploading.set()
		if interface1enable == '1':
			os.system(monitor_disable1)
		if interface2enable == '1':
			os.system(monitor_disable2)
		if interface3enable == '1':
			os.system(monitor_disable3)
#This will change the channels every 1 sec to scan all in the range. 
def rotator():
	def rotate(stop):
		while not stop.is_set():
			try:
				if interface1enable == '1': #This loop is for interface 1
					channel1 = str(random.choice(channels1))
					logging.info('Changing to channel for interface1 ' + channel1)
					os.system(change_channel1 % channel1)
				if interface2enable == '1': #This loop is for interface 2
					channel2 = str(random.choice(channels2))
					logging.info('Changing to channel for interface2 ' + channel2)
					os.system(change_channel2 % channel2)
				if interface3enable == '1': #This loop is for interface 3
					channel3 = str(random.choice(channels3))
					logging.info('Changing to channel for interface3 ' + channel3)
					os.system(change_channel3 % channel3)
				time.sleep(1) # seconds
			except KeyboardInterrupt: pass
	stop = multiprocessing.Event()
	multiprocessing.Process(target=rotate, args=[stop]).start()
	return stop
#this is the caputre fuction, It will only caputre the mgt frames.
def sniffer():
	print "sniffer started"

	commands = [
    'tcpdump -i wlan1mon -G 600 --packet-buffered -W 144 -e -s 512 type mgt -w /data/incoming/wlan1-%Y-%m-%d_%H.%M.%S.pcap;',
    'tcpdump -i wlan2mon -G 600 --packet-buffered -W 144 -e -s 512 type mgt -w /data/incoming/wlan2-%Y-%m-%d_%H.%M.%S.pcap;',
    'tcpdump -i wlan0mon -G 600 --packet-buffered -W 144 -e -s 512 type mgt -w /data/incoming/wlan0-%Y-%m-%d_%H.%M.%S.pcap;',
]


# run in parallel
	processes = [Popen(cmd, shell=True) for cmd in commands]
# do other things here..
# wait for completion
	for p in processes: p.wait()


#	def sniffing(stop):
#		while not stop.is_set():
#			try:
#				if interface1enable == '1':
#					pone = Popen('tcpdump -i wlan0mon -G 600 --packet-buffered -W 144 -e -s 512 type mgt -w /data/incoming/wlan0-%Y-%m-%d_%H.%M.%S.pcap')
#				if interface2enable == '1':
#					ptwo = Popen('tcpdump -i wlan1mon -G 600 --packet-buffered -W 144 -e -s 512 type mgt -w /data/incoming/wlan1-%Y-%m-%d_%H.%M.%S.pcap')
#					print "tcpdump on wlan1mon would have started"
#				if interface3enable == '1':
#					pthree = Popen('tcpdump -i wlan2mon -G 600 --packet-buffered -W 144 -e -s 512 type mgt -w /data/incoming/wlan2-%Y-%m-%d_%H.%M.%S.pcap')
#					print "tcpdump on wlan2mon would have started"
#				if interface4enable == '1':
#				subprocess.Popen('tcpdump -i wlan4mon -G 600 --packet-buffered -W 144 -e -s 512 type mgt -w /data/incoming/wlan4-%Y-%m-%d_%H.%M.%S.pcap', shell=True).wait()
#				print "tcpdump on wlan4mon would have started"
#				return pone, ptwo, pthree
#			except KeyboardInterrupt: pass
#	stop = multiprocessing.Event()
#	multiprocessing.Process(target=sniffing, args=[stop]).start()
#	pone.terminate()
#	ptwo.terminate()
#	pthree.terminate()
#	p4.terminate()
#	return stop
	
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