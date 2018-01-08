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

#1 is enabled, 0 is disabled
interface1enable = '1'
interface1 = 'wlan1mon'
monitor_enable1  = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
monitor_disable1 = 'iw dev wlan1mon del; ifconfig wlan1 up'
change_channel1  = 'iw dev wlan1mon set channel %s'
channels1 = [6, 48, 1, 11, 36, 40] #use the linux command "iwlist channel" to get a list of every channel your devices supports)

#At this more than interface has not been tested
#1 is enabled, 0 is disabled
interface2enable = '0'
interface2 = 'wlan1mon'
monitor_enable2  = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
monitor_disable2 = 'iw dev wlan1mon del; ifconfig wlan1 up'
change_channel2  = 'iw dev wlan1mon set channel %s'
channels2 = [6, 48, 1, 11, 36, 40] #use the linux command "iwlist channel" to get a list of every channel your devices supports)

#At this more than interface has not been tested
#1 is enabled, 0 is disabled
interface3enable = '0'
interface3 = 'wlan1mon'
monitor_enable3  = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
monitor_disable3 = 'iw dev wlan1mon del; ifconfig wlan1 up'
change_channel3  = 'iw dev wlan1mon set channel %s'
channels3 = [6, 48, 1, 11, 36, 40] #use the linux command "iwlist channel" to get a list of every channel your devices supports)

#At this more than interface has not been tested
#1 is enabled, 0 is disabled
interface4enable = '0'
interface4 = 'wlan1mon'
monitor_enable4  = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
monitor_disable4 = 'iw dev wlan1mon del; ifconfig wlan1 up'
change_channel4  = 'iw dev wlan1mon set channel %s'
channels = [6, 48, 1, 11, 36, 40] #use the linux command "iwlist channel" to get a list of every channel your devices supports)

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
	if interface2enable == '1':
		os.system(monitor_enable1)
	if interface3enable == '1':
		os.system(monitor_enable1)
	if interface4enable == '1':
		os.system(monitor_enable1)
	stop_rotating = rotator()
	stop_uploading = uploader()
	try:sniffer()
	except KeyboardInterrupt: sys.exit()
	finally:
		print "Please wait for everything to stop"
		stop_rotating.set()
		stop_uploading.set()
		if interface1enable == '1':
			os.system(monitor_disable1)
		if interface2enable == '1':
			os.system(monitor_disable2)
		if interface3enable == '1':
			os.system(monitor_disable3)
		if interface4enable == '1':
			os.system(monitor_disable4)
#This will change the channels every 1 sec to scan all in the range. 
def rotator():
	def rotate(stop):
		while not stop.is_set():
			try:
				if interface1enable == '1': #This loop is for interface 1
					channel1 = str(random.choice(channels1))
					logging.info('Changing to channel ' + channel1)
					os.system(change_channel1 % channel1)
				if interface2enable == '1': #This loop is for interface 2
					channel2 = str(random.choice(channels2))
					logging.info('Changing to channel ' + channel2)
					os.system(change_channel2 % channel2)
				if interface3enable == '1': #This loop is for interface 3
					channel3 = str(random.choice(channels3))
					logging.info('Changing to channel ' + channel3)
					os.system(change_channel3 % channel3)
				if interface4enable == '1': #This loop is for interface 4
					channel4 = str(random.choice(channels4))
					logging.info('Changing to channel ' + channel4)
					os.system(change_channel4 % channel4)
				time.sleep(1) # seconds
			except KeyboardInterrupt: pass
	stop = multiprocessing.Event()
	multiprocessing.Process(target=rotate, args=[stop]).start()
	return stop
#this is the caputre fuction, It will only caputre the mgt frames.
def sniffer():
	if interface1enable == '1':
		subprocess.call('tcpdump -i wlan1mon -G 600 --packet-buffered -W 144 -e -s 512 type mgt -w /data/incoming/trace-%Y-%m-%d_%H.%M.%S.pcap', shell=True)
	if interface2enable == '1':
		print "interface2 sniffer would have ran"
	if interface3enable == '1':
		print "interface3 sniffer would have ran"
	if interface4enable == '1':
		print "interface4 sniffer would have ran"
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
