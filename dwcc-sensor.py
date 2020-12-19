#!/usr/bin/env python
import sys
import os
import logging
import random
import time
import multiprocessing
import socket
import subprocess
import os.path
import pysftp
from subprocess import Popen



#1 is enabled, 0 is disabled
interface0enable = '1'
#Change the below to match your systems wifi interface name
interface0 = 'wlx00c0ca957c18'
monitor_enable0  = 'ifconfig ' + interface0 + ' down; iw dev ' + interface0 + ' interface add wlan0mon type monitor; ifconfig wlan0mon down; iw dev wlan0mon set type monitor; ifconfig wlan0mon up'
monitor_disable0 = 'iw dev wlan0mon del; ifconfig ' + interface0 + ' up'
change_channel0  = 'iw dev wlan0mon set channel %s'
#channels0 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116] #use the linux command "iwlist channel" to get a list of every channel your devices supports)
channels0 = [1, 6, 11] #use the linux command "iwlist channel" to get a list of every channel your devices supports)

#At this more than interface has not been tested
#1 is enabled, 0 is disabled
interface1enable = '0'
interface1 = 'wlan1mon'
monitor_enable1  = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
monitor_disable1 = 'iw dev wlan1mon del; ifconfig wlan1 up'
change_channel1  = 'iw dev wlan1mon set channel %s'
channels1 = [120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165] #use the linux command "iwlist channel" to get a list of every channel your devices supports)

#At this point only 3 interfaces have been tested
#1 is enabled, 0 is disabled
interface2enable = '0'
interface2 = 'wlan2mon'
monitor_enable2 = 'ifconfig wlan2 down; iw dev wlan2 interface add wlan2mon type monitor; ifconfig wlan2mon down; iw dev wlan2mon set type monitor; ifconfig wlan2mon up'
monitor_disable2 = 'iw dev wlan2mon del; ifconfig wlan2 up'
change_channel2  = 'iw dev wlan2mon set channel %s'
channels2 = [1, 6, 11] #use the linux command "iwlist channel" to get a list of every channel your devices supports)

#1 is enabled, 0 is disabled
#interface3enable = '1'
#interface3 = 'wlan3mon'
#monitor_enable3  = 'ifconfig wlan3 down; iw dev wlan3 interface add wlan3mon type monitor; ifconfig wlan3mon down; iw dev wlan3mon set type monitor; ifconfig wlan3mon up'
#monitor_disable3 = 'iw dev wlan3mon del; ifconfig wlan3 up'
#change_channel3  = 'iw dev wlan3mon set channel %s'
#channels1 = [6, 48, 1, 11, 36, 40, 44, 10 ] #use the linux command "iwlist channel" to get a list of every channel your devices supports)

#info for sftp server
sshhost = '10.1.0.7'  #can be hostname or ip
sshuser = 'zach'           #make sure that key auth is working



hostname = socket.gethostname()

queue = multiprocessing.Queue()
incomingpath = '/data/incoming/' #This is the path where new pcaps will be placed


#This is the main function
def start():
	try:
		os.remove("/root/Distributed-Wifi-Capability-Collector/dwcc.log")
	except OSError:
		pass
	subprocess.call('iw reg set US', shell=True)
	logging.basicConfig(filename='/root/Distributed-Wifi-Capability-Collector/dwcc.log', format='%(levelname)s:%(message)s', level=logging.INFO)

	if interface0enable == '1':
		os.system(monitor_enable0)
		logging.info("starting wlan0")
	if interface1enable == '1':
		os.system(monitor_enable1)
		logging.info("starting wlan1")
	if interface2enable == '1':
		os.system(monitor_enable2)
		logging.info("starting wlan2")
	stop_rotating = rotator()
	stop_uploading = uploader()
	try:sniffer()
	except KeyboardInterrupt: sys.exit()
	finally:
		print "Please wait for everything to stop"
		stop_rotating.set()
		stop_uploading.set()
		if interface0enable == '1':
			os.system(monitor_disable0)
		if interface1enable == '1':
			os.system(monitor_disable1)
		if interface2enable == '1':
			os.system(monitor_disable2)

#This will change the channels every 5 sec to scan all in the range.
def rotator():
	def rotate(stop):
		while not stop.is_set():
			try:
				if interface0enable == '1': #This loop is for interface 0
					channel1 = str(random.choice(channels0))
					logging.info('Changing to channel for interface0 ' + channel0)
					os.system(change_channel0 % channel0)
				if interface1enable == '1': #This loop is for interface 1
					channel2 = str(random.choice(channels1))
					logging.info('Changing to channel for interface1 ' + channel1)
					os.system(change_channel1 % channel1)
				if interface2enable == '1': #This loop is for interface 2
					channel2 = str(random.choice(channels2))
					logging.info('Changing to channel for interface2 ' + channel2)
					os.system(change_channel2 % channel2)
				time.sleep(5) # seconds
			except KeyboardInterrupt: pass
	stop = multiprocessing.Event()
	multiprocessing.Process(target=rotate, args=[stop]).start()
	return stop
#this is the capture function, It will only capture the mgt frames.
def sniffer():
	logging.info("sniffer started")
	if interface0enable == '1':  # This loop is for interface 0

		commands = [
   			 'tcpdump -i wlan3mon -G 600 --packet-buffered -W 300 -e -s 1024 type mgt or type ctl -w '+incomingpath +''+ hostname +'-wlan0mon-%Y-%m-%d_%H.%M.%S.pcap;',
		]
	if interface1enable == '1':  # This loop is for interface 1

		commands = [
			'tcpdump -i wlan1mon -G 600 --packet-buffered -W 300 -e -s 1024 type mgt or type ctl -w ' + incomingpath + '' + hostname + '-wlan1mon-%Y-%m-%d_%H.%M.%S.pcap;',
		]
	if interface2enable == '2':  # This loop is for interface 2

			commands = [
				'tcpdump -i wlan2mon -G 600 --packet-buffered -W 300 -e -s 1024 type mgt or type ctl -w ' + incomingpath + '' + hostname + '-wlan2mon-%Y-%m-%d_%H.%M.%S.pcap;',
			]
# tcpdump -i wlan0mon  -G 600 --packet-buffered -W 300 -e -s 1024 type mgt or type ctl -w - | tee /home/zach/somefile1.pcap | tshark -i -   -T fields -e wlan.sa -e radiotap.dbm_antsignal | awk 'NF==2'
# run in parallel
	processes = [Popen(cmd, shell=True) for cmd in commands]

	# wait for completion
	for p in processes: p.wait()

#the above will rotate the pcap every  5  mins and keeps 24 hours worth
def uploader():
	def upload(stop):
		while not stop.is_set():
			try:
				for fname in os.listdir(incomingpath):
					if fname.endswith('.pcap'):
						try:
							with pysftp.Connection(host=sshhost, username=sshuser, private_key='~/.ssh/id_rsa') as sftp:
								with sftp.cd(incomingpath):
									sftp.put(incomingpath +fname)
							logging.info("uploaded pcap") 
						except pysftp.SSHException:
							logging.info("Unable to establish SSH connection will retry in 5 min")
							time.sleep(300) #seconds
					os.remove(incomingpath +fname)
				else:
					logging.info("no pcap found, will try again in 5 min")
					time.sleep(300) #seconds
			except KeyboardInterrupt: pass
	stop = multiprocessing.Event()
	multiprocessing.Process(target=upload, args=[stop]).start()
	return stop
start()
