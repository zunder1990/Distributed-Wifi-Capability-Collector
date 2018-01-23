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
import plotly

#import plotly.plotly as py
#import plotly.graph_objs as go


#This change the below to reflect your sysrem
incomingpath = '/data/incoming/' #This is the path where new pcaps will be placed
archivepath = '/data/archive/' #This is the path where pcaps what already have been checked will be placed
tmppath = '/data/tmp/' #this is the path for a tmp folder for dwcc to use
DB_FILE = 'dwcc.db'
#you may change the path but please dont change the filename
csvfile = '/data/tmp/dwcc-clients.csv'

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
			macaddressconverterclient()
			macaddressconverterap()
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
	cursor.execute('DELETE FROM dwccincoming WHERE ID NOT IN (SELECT min(ID) FROM dwccincoming GROUP BY wlansa, radiotapchannelflags2ghz, radiotapchannelflags2ghz);')
	cursor.execute('DELETE FROM dwccap WHERE ID NOT IN (SELECT min(ID) FROM dwccap GROUP BY wlanbssid, wlanmgtssid);')
	conn.commit()
	print "finish dedup"

def rowcount():
	cursor.execute('SELECT COUNT(*)FROM dwccincoming;')
	numberofclient=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*)FROM dwccap;')
	numberofap=cursor.fetchone()[0]
	print "Total number of clients found in the database = ", numberofclient
	print "Total number of APs found in the database = ", numberofap
#working on this
def charting():
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb19 = 1;')
	b19supportcount=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesshort80 = 1;')
	ngi80mhzsupportcount=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesshort160 = 1;')
	ngi160mhzsupportcount=cursor.fetchone()[0]
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
	cursor.execute('SELECT wlansaconverted, count(wlansaconverted) FROM dwccincoming GROUP BY wlansaconverted ORDER BY count(wlansaconverted) DESC limit 10;')
	devicemaker=cursor.fetchall()
	cursor.execute('SELECT wlanradiochannel, count(wlanradiochannel) FROM dwccincoming GROUP BY wlanradiochannel ORDER BY count(wlanradiochannel) DESC limit 10;')
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
	cursor.execute('SELECT wlanmgtpowercapmax, count(wlanmgtpowercapmax) FROM dwccincoming GROUP BY wlanmgtpowercapmax ORDER BY count(wlanmgtpowercapmax);')
	wlanmgtpowercapmax=cursor.fetchall()
	cursor.execute('SELECT wlanmgtpowercapmin, count(wlanmgtpowercapmin) FROM dwccincoming GROUP BY wlanmgtpowercapmin ORDER BY count(wlanmgtpowercapmin);')
	wlanmgtpowercapmin=cursor.fetchall()
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtfixedcapabilitiesspecman = 1;')
	wlanmgtfixedcapabilitiesspecman=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtfixedcapabilitiesradiomeasurement = 1;')
	wlanmgtfixedcapabilitiesradiomeasurement=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessupportedchanwidthset = 1;')
	wlanmgtvhtcapabilitiessupportedchanwidthset1=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessupportedchanwidthset = 2;')
	wlanmgtvhtcapabilitiessupportedchanwidthset2=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesrxldpc = 1;')
	wlanmgtvhtcapabilitiesrxldpc=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiestxstbc = 1;')
	wlanmgtvhtcapabilitiestxstbc=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb1 = 1;')
	wlanmgtextcapb1=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb2 = 1;')
	wlanmgtextcapb2=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb3 = 1;')
	wlanmgtextcapb3=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb4 = 1;')
	wlanmgtextcapb4=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb6 = 1;')
	wlanmgtextcapb6=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb8 = 1;')
	wlanmgtextcapb8=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb9 = 1;')
	wlanmgtextcapb9=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb10 = 1;')
	wlanmgtextcapb10=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb11 = 1;')
	wlanmgtextcapb11=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb12 = 1;')
	wlanmgtextcapb12=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb13 = 1;')
	wlanmgtextcapb13=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb14 = 1;')
	wlanmgtextcapb14=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb15 = 1;')
	wlanmgtextcapb15=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb16 = 1;')
	wlanmgtextcapb16=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb17 = 1;')
	wlanmgtextcapb17=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb18 = 1;')
	wlanmgtextcapb18=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb20 = 1;')
	wlanmgtextcapb20=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb21 = 1;')
	wlanmgtextcapb21=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb22 = 1;')
	wlanmgtextcapb22=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb23 = 1;')
	wlanmgtextcapb23=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb24 = 1;')
	wlanmgtextcapb24=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb25 = 1;')
	wlanmgtextcapb25=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb26 = 1;')
	wlanmgtextcapb26=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb27 = 1;')
	wlanmgtextcapb27=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb28 = 1;')
	wlanmgtextcapb28=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb29 = 1;')
	wlanmgtextcapb29=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb30 = 1;')
	wlanmgtextcapb30=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb33 = 1;')
	wlanmgtextcapb33=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb34 = 1;')
	wlanmgtextcapb34=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE radiotapchannelflagsofdm = 1;')
	radiotapchannelflagsofdm=cursor.fetchone()[0]
	cursor.execute('SELECT wlanmgtvhtcapabilitiesmaxmpdulength, count(wlanmgtvhtcapabilitiesmaxmpdulength) FROM dwccincoming GROUP BY wlanmgtvhtcapabilitiesmaxmpdulength ORDER BY count(wlanmgtvhtcapabilitiesmaxmpdulength) DESC;')
	wlanmgtvhtcapabilitiesmaxmpdulength=cursor.fetchall()
	cursor.execute('SELECT wlanmgtssid, count(wlanmgtssid) FROM dwccincoming GROUP BY wlanmgtssid ORDER BY count(wlanmgtssid) DESC limit 20;')
	wlanmgtssid=cursor.fetchall()
	cursor.execute('SELECT wlanmgtssid, count(wlanmgtssid) FROM dwccap GROUP BY wlanmgtssid ORDER BY count(wlanmgtssid) DESC limit 20;')
	wlanmgtssidap=cursor.fetchall()
	cursor.execute('SELECT wlansaconverted, count(wlansaconverted) FROM dwccap GROUP BY wlansaconverted ORDER BY count(wlansaconverted) DESC limit 20;')
	apmaker=cursor.fetchall()
	cursor.execute('SELECT wlanradiochannel, count(wlanradiochannel) FROM dwccap GROUP BY wlanradiochannel ORDER BY count(wlanradiochannel) DESC;')
	channelgroupap=cursor.fetchall()
	print "Total number of clients found to support Sounding Dimensions of 1 = ", soundingdimensions0
	print "Total number of clients found to support Sounding Dimensions of 0 = ", soundingdimensions1
	print "Total number of clients found to support Sounding Dimensions of 3 = ", soundingdimensions3
	print "Total number of clients found to support BSS Transition aka 802.11r aka FT = ", b19supportcount
	print "Total number of clients found to support short Guard Interval 80mhz channel in 5ghz = ", ngi80mhzsupportcount
	print "Total number of clients found to support short Guard Interval160mhz channel in 5ghz = ", ngi160mhzsupportcount
	
	print "Total number of clients that support interworking this is reated to 802.11u= ", n80211usupport
	print "Total number of clients that support QOS map= ", qosmapsupport
	print "Total number of clients that support wnm notification= ", wnmsupport
	print "Total number of clients that support can recive frames from mu-mino AP= ", wlanmgtvhtcapabilitiesmubeamformee
	print "Total number of clients that support can send frames from mu-mino AP= ", wlanmgtvhtcapabilitiesmubeamformer
	print "Total number of clients that support can recive frames from single user beamforming AP= ", wlanmgtvhtcapabilitiessubeamformee
	print "Total number of clients that support can send frames from single user beamforming AP= ", wlanmgtvhtcapabilitiessubeamformer
	print "power max = ", wlanmgtpowercapmax
	print "power min = ", wlanmgtpowercapmin
	print "Total number of clients that support 802.11h/dfs channels. This will only show on 5ghz clients = ", wlanmgtfixedcapabilitiesspecman
	print "Maximum MPDU Length in bytes = "  , wlanmgtvhtcapabilitiesmaxmpdulength
	
	print "total number of clients that support 160hmz contiguous only = ", wlanmgtvhtcapabilitiessupportedchanwidthset1
	print "total number of clients that support 160hmz contiguous and 80+80 = ", wlanmgtvhtcapabilitiessupportedchanwidthset2
	print "Total number of clients that can receive LDPC-encoded frames = ", wlanmgtvhtcapabilitiesrxldpc
	print "Total number of clients that can Tansmission of STBC-coded frames = ", wlanmgtvhtcapabilitiestxstbc
	print "Total number for clients that support On-demand beacon realted to 802.11p = ", wlanmgtextcapb1
	print "Total number for clients that support Extended Channel Switching  = ", wlanmgtextcapb2
	print "Total number for clients that support WAVE indication this is 802.11p = ", wlanmgtextcapb3
	print "Total number for clients that support PSMP Capability  = ", wlanmgtextcapb4
	print "Total number for clients that support Scheduled PSMP = ", wlanmgtextcapb6
	print "Total number for clients that support Diagnostic Report = ", wlanmgtextcapb8
	print "Total number for clients that support Multicast Diagnostics = ", wlanmgtextcapb9
	print "Total number for clients that support Orthogonal Frequency-Division Multiplexing OFDM = ", radiotapchannelflagsofdm
	print "Total number for clients that support Location Tracking = ", wlanmgtextcapb10
	print "Total number for clients that support Flexible Multicast Service = ", wlanmgtextcapb11
	print "Total number for clients that support Proxy ARP in 802.11-2012 = ", wlanmgtextcapb12
	print "Total number for clients that support Collocated Interference Reporting = ", wlanmgtextcapb13
	print "Total number for clients that support Civic Location = ", wlanmgtextcapb14
	print "Total number for clients that support Geospatial Location = ", wlanmgtextcapb15
	print "Total number for clients that support TFS = ", wlanmgtextcapb16
	print "Total number for clients that support WNM-Sleep Mode = ", wlanmgtextcapb17
	print "Total number for clients that support TIM Broadcast = ", wlanmgtextcapb18
	print "Total number for clients that support QoS Traffic Capability = ", wlanmgtextcapb20
	print "Total number for clients that support AC Station Count = ", wlanmgtextcapb21
	print "Total number for clients that support Multiple BSSID = ", wlanmgtextcapb22
	print "Total number for clients that support Timing Measurement = ", wlanmgtextcapb23
	print "Total number for clients that support Channel Usage = ", wlanmgtextcapb24
	print "Total number for clients that support SSID List = ", wlanmgtextcapb25
	print "Total number for clients that support DMS = ", wlanmgtextcapb26
	print "Total number for clients that support UTC TSF Offset = ", wlanmgtextcapb27
	print "Total number for clients that support Peer U-APSD Buffer STA Support = ", wlanmgtextcapb28
	print "Total number for clients that support TDLS Peer PSM Support = ", wlanmgtextcapb29
	print "Total number for clients that support TDLS channel switching = ", wlanmgtextcapb30
	print "Total number for clients that support EBR = ", wlanmgtextcapb33
	print "Total number for clients that support SSPN Interface = ", wlanmgtextcapb34
	print "ssid that clients was trying to connect to (top 20) = ", wlanmgtssid
	print "APs per ssid found (top20) = ", wlanmgtssidap
	print "AP vendors (top20) =", apmaker
	print "The channel the APs was found on = ", channelgroupap

	labelschannelgroup = []
	valueschannelgroup = []
	for i in channelgroup:
		labelschannelgroup.append(str(i[0]))
		valueschannelgroup.append(i[1])

	labelsdevicemaker = []
	valuesdevicemaker = []
	for i in devicemaker:
		labelsdevicemaker.append(str(i[0]))
		valuesdevicemaker.append(i[1])
#	trace = plotly.graph_objs.Pie(labels=labels, values=values)

	# dumps results to html file and opens file with default system browser
#	plotly.offline.plot([trace], filename="mac_vendors.html")
	fig = {
  "data": [
    {
      "values": valuesdevicemaker,
      "labels": labelsdevicemaker,
      "domain": {"x": [0, .48]},
      "hoverinfo":"label+percent",
      "hole": .4,
      "type": "pie"
    },
    {
      "values": valueschannelgroup,
      "labels": labelschannelgroup,
      "textposition":"inside",
      "domain": {"x": [.52, 1]},
      "hoverinfo":"label+percent",
      "hole": .4,
      "type": "pie"
    }],
  "layout": {
        "title":"Client info",
		"showlegend": False,
        "annotations": [
            {
                "font": {
                    "size": 20
                },
                "showarrow": False,
                "text": "MAC address Marker of client",
                "x": 0.20,
                "y": 0.5
            },
            {
                "font": {
                    "size": 20
                },
                "showarrow": False,
                "text": "Channel",
                "x": 0.8,
                "y": 0.5
            }
        ]
    }
}
	clientchart = plotly.offline.plot(fig, include_plotlyjs=False, output_type='div')
	print 
	f = open('/var/www/html/display.html','w')
	f.write("""
<html>
<head>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
<p>
<table style="width: 100%">
<tr>
<th>Description</th>
<th>Number of clients that support it</th>
<th>Description</th>
<th>Number of clients that support it</th>
</tr>
<tr>
<th>5 ghz clients</th>
<th>""" + str(n5ghzclientcount) + """</th>
<th>2 ghz clients</th>
<th>""" + str(n2ghzclientcount) + """</th>
</tr>
<tr>
<th>802.11k</th>
<th>""" + str(wlanmgtfixedcapabilitiesradiomeasurement) + """</th>
<th>802.11w</th>
<th>""" + str(n80211wsupport) + """</th>
</tr>
</table>
</p>
""" + str(clientchart) + """
</body>
</html>
""")
	f.close()
def dbconverter():
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessoundingdimensions = '1' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000001';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessoundingdimensions = '0' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000000';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessoundingdimensions = '3' WHERE wlanmgtvhtcapabilitiessoundingdimensions  = '0x00000002';")
	cursor.execute("UPDATE dwccincoming SET wlansaconverted = 'vendornotfound' WHERE wlansaconverted  = 'None';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiesmaxmpdulength = '11454' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000002';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiesmaxmpdulength = '7991' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000001';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiesmaxmpdulength = '3895' WHERE wlanmgtvhtcapabilitiesmaxmpdulength  = '0x00000000';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessupportedchanwidthset = '0' WHERE wlanmgtvhtcapabilitiessupportedchanwidthset  = '0x00000000';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessupportedchanwidthset = '1' WHERE wlanmgtvhtcapabilitiessupportedchanwidthset  = '0x00000001';")
	cursor.execute("UPDATE dwccincoming SET wlanmgtvhtcapabilitiessupportedchanwidthset = '2' WHERE wlanmgtvhtcapabilitiessupportedchanwidthset  = '0x00000002';")
	cursor.execute("UPDATE dwccap SET wlansaconverted = 'vendornotfound' WHERE wlansaconverted  = 'None';")
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
						subprocess.call('tshark -r ' + pcapfile + '   -R "wlan.fc.type_subtype == 0x0 or wlan.fc.type_subtype == 0x2" -2 -T fields -e wlan.sa -e wlan.bssid -e radiotap.channel.freq -e wlan_mgt.extcap.b19 -e wlan.fc.protected \
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
-e wlan_mgt.vht.mcsset.txmcsmap.ss1 -e wlan_mgt.vht.mcsset.txmcsmap.ss2 -e wlan_mgt.vht.mcsset.txmcsmap.ss3 -e wlan_mgt.vht.mcsset.txmcsmap.ss4 -e wlan_mgt.ssid \
-E separator=+ >> ' + tmppath + 'dwcc-clients.csv', shell=True)
						subprocess.call('tshark -r ' + pcapfile + '   -R "wlan.fc.type_subtype == 0x8" -2 -T fields -e wlan_radio.channel -e wlan_mgt.ssid -e wlan.bssid -E separator=+ >> ' + tmppath + 'dwcc-ap.csv', shell=True)

			#this below will move the pcap into the archive folder
						os.rename(incomingpath +fname, archivepath +fname)
						print "pcap found and tshark has ran"
					else:
						print "No pcap found waiting 5 mins to rerun"

def macaddressconverterclient():
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
		conn.commit()
		macaddressconverterclient()

		
		
def macaddressconverterap():
	for i in range(50):
		p = manuf.MacParser(update=True)
		cursor.execute("""SELECT wlanbssid from dwccap WHERE wlansaconverted IS NULL OR wlansaconverted = '' limit 1;""")
		mactochange = cursor.fetchone()
	
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
			cursor.execute("UPDATE dwccap SET wlansaconverted = "+ `changedmacstr` +" WHERE wlanbssid  = "+ `mactochangestr` +"   ;")
#			macaddressconverterap()
	conn.commit()
	print "finished a round up to 50 AP mac"
	
		
		
		
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
			conn.execute('INSERT INTO dwccincoming(wlansa, wlanbssid, radiotapchannelfreq, wlanmgtextcapb19, wlanfcprotected, \
wlanradiochannel, wlanfcpwrmgt, wlanmgtfixedcapabilitiesradiomeasurement, wlanmgthtmcssettxmaxss, \
radiotapchannelflagsofdm, radiotapchannelflags5ghz, radiotapchannelflags2ghz, wlanmgtfixedcapabilitiesspecman, \
wlanmgtpowercapmax, wlanmgtpowercapmin, wlanmgtrsncapabilitiesmfpc, wlanmgtextcapb31, wlanmgtextcapb32, wlanmgtextcapb46, \
wlanmgttagnumber, wlanmgtvhtcapabilitiesmaxmpdulength, wlanmgtvhtcapabilitiessupportedchanwidthset, wlanmgtvhtcapabilitiesrxldpc, \
wlanmgtvhtcapabilitiesshort80, wlanmgtvhtcapabilitiesshort160, wlanmgtvhtcapabilitiestxstbc, wlanmgtvhtcapabilitiessubeamformer, \
wlanmgtvhtcapabilitiessubeamformee, wlanmgtvhtcapabilitiesbeamformerants, wlanmgtvhtcapabilitiessoundingdimensions, wlanmgtvhtcapabilitiesmubeamformer, \
wlanmgtvhtcapabilitiesmubeamformee, wlanmgttagoui,  wlanmgtfixedcapabilitiesess, radiotapantenna, \
wlanmgtextcapb4, wlanmgtextcapb3, wlanmgtextcapb2, wlanmgtextcapb1, wlanmgtextcapb6, wlanmgtextcapb8, wlanmgtextcapb9, wlanmgtextcapb10, wlanmgtextcapb11, wlanmgtextcapb12, \
wlanmgtextcapb13, wlanmgtextcapb14, wlanmgtextcapb15, wlanmgtextcapb16, wlanmgtextcapb17, wlanmgtextcapb18, wlanmgtextcapb20, wlanmgtextcapb21, wlanmgtextcapb22, wlanmgtextcapb23, \
wlanmgtextcapb24, wlanmgtextcapb25, wlanmgtextcapb26, wlanmgtextcapb27, wlanmgtextcapb28, wlanmgtextcapb29, wlanmgtextcapb30, wlanmgtextcapb33, wlanmgtextcapb34, wlanmgtextcapb35, \
wlanmgtextcapb36, wlanmgtextcapb37, wlanmgtextcapb38, wlanmgtextcapb39, wlanmgtextcapb40, wlanmgtextcapservintgranularity, wlanmgtextcapb44, wlanmgtextcapb45, wlanmgtextcapb47, \
wlanmgtextcapb48, wlanmgtextcapb61, wlanmgtextcapb62, wlanmgtextcapb63, wlanmgtvhtcapabilitiesrxstbc, wlanmgtvhtmcssetrxmcsmapss1, wlanmgtvhtmcssetrxmcsmapss2, wlanmgtvhtmcssetrxmcsmapss3, \
wlanmgtvhtmcssetrxmcsmapss4, wlanmgtvhtmcssettxmcsmapss1, wlanmgtvhtmcssettxmcsmapss2, wlanmgtvhtmcssettxmcsmapss3, wlanmgtvhtmcssettxmcsmapss4, wlanmgtssid)' \
'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', row)
		conn.commit()
#This will remove the file after it is added to the db
		os.remove(csvfileclient)
		print "done with dbupdate for client waiting for next run"
	else:
		print"csv client not found will retry"

	csvfileap = '/data/tmp/dwcc-ap.csv'
	#this will check for the CSV file, If it is found then import it into the database. If no CSV is found then it move on
	if os.path.isfile(csvfileap) and os.access(csvfileap, os.R_OK):
		print "ap csv found adding to db"
		subprocess.call("""cat /data/tmp/dwcc-ap.csv | awk '!seen[$0]++' | sed -e 's/ /-/g' -e 's/[<>"^()@#&!$.,]//g' -e "s/'//g" -e '/^$/d' | awk 'BEGIN{FS=OFS="+"} NF==4 {$0=$1 OFS $2 $3 OFS $4} {print}' >> /data/tmp/temp-dwcc-ap.csv """, shell=True)
		os.remove("/data/tmp/dwcc-ap.csv")
		os.rename("/data/tmp/temp-dwcc-ap.csv", "/data/tmp/dwcc-ap.csv")
		csv_dataap = csv.reader(file(csvfileap), delimiter='+')
		for rowap in csv_dataap:
			conn.execute('INSERT INTO dwccap (wlanradiochannel, wlanmgtssid, wlanbssid)' 'VALUES (?,?,?)', rowap)
		conn.commit()
#This will remove the file after it is added to the db
		os.remove(csvfileap)
		print "done with dbupdate for ap waiting for next run"
	else:
		print"csv ap not found will retry"

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
wlanmgtssid char(200),
wlansaconverted char(200),
wlanmgtextcapb4 char(50),
wlanmgtextcapb3 char(50),
wlanmgtextcapb2 char(50),
wlanmgtextcapb1 char(50),
wlanmgtextcapb6 char(50),
wlanmgtextcapb8 char(50),
wlanmgtextcapb9 char(50),
wlanmgtextcapb10 char(50),
wlanmgtextcapb11 char(50),
wlanmgtextcapb12 char(50),
wlanmgtextcapb13 char(50),
wlanmgtextcapb14 char(50),
wlanmgtextcapb15 char(50),
wlanmgtextcapb16 char(50),
wlanmgtextcapb17 char(50),
wlanmgtextcapb18 char(50),
wlanmgtextcapb20 char(50),
wlanmgtextcapb21 char(50),
wlanmgtextcapb22 char(50),
wlanmgtextcapb23 char(50),
wlanmgtextcapb24 char(50),
wlanmgtextcapb25 char(50),
wlanmgtextcapb26 char(50),
wlanmgtextcapb27 char(50),
wlanmgtextcapb28 char(50),
wlanmgtextcapb29 char(50),
wlanmgtextcapb30 char(50),
wlanmgtextcapb33 char(50),
wlanmgtextcapb34 char(50),
wlanmgtextcapb35 char(50),
wlanmgtextcapb36 char(50),
wlanmgtextcapb37 char(50),
wlanmgtextcapb38 char(50),
wlanmgtextcapb39 char(50),
wlanmgtextcapb40 char(50),
wlanmgtextcapservintgranularity char(50),
wlanmgtextcapb44 char(50),
wlanmgtextcapb45 char(50),
wlanmgtextcapb47 char(50),
wlanmgtextcapb48 char(50),
wlanmgtextcapb61 char(50),
wlanmgtextcapb62 char(50),
wlanmgtextcapb63 char(50),
wlanmgtvhtcapabilitiesrxstbc char(50),
wlanmgtvhtmcssetrxmcsmapss1 char(50),
wlanmgtvhtmcssetrxmcsmapss2 char(50),
wlanmgtvhtmcssetrxmcsmapss3 char(50),
wlanmgtvhtmcssetrxmcsmapss4 char(50),
wlanmgtvhtmcssettxmcsmapss1 char(50),
wlanmgtvhtmcssettxmcsmapss2 char(50),
wlanmgtvhtmcssettxmcsmapss3 char(50),
wlanmgtvhtmcssettxmcsmapss4 char(50));''')

	cursor.execute('''CREATE TABLE if not exists dwccap
(ID INTEGER PRIMARY KEY autoincrement NOT NULL,
wlanbssid char(50),
wlanradiochannel char(50),
wlanmgtssid char(200),
wlansaconverted char(200));''')

	conn.commit()

start()
