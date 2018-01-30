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
import re



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
			dbconverter()
			charting()
##			mergecap()
			macaddressconverterclient()
			macaddressconverterap()
			macaddressconverterprobe()
			heatmapprep()
			heatmapping()
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
	cursor.execute('DELETE FROM dwccincoming WHERE ID NOT IN (SELECT min(ID) FROM dwccincomingprobe GROUP BY wlansa, radiotapchannelflags2ghz, radiotapchannelflags2ghz);')
	cursor.execute('DELETE FROM dwccap WHERE ID NOT IN (SELECT min(ID) FROM dwccap GROUP BY wlanbssid, wlanmgtssid);')
	conn.commit()
	print "finish dedup"

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
	cursor.execute('SELECT wlanmgtpowercapmax, count(wlanmgtpowercapmax) FROM dwccincoming GROUP BY wlanmgtpowercapmax ORDER BY count(wlanmgtpowercapmax) DESC limit 5;')
	wlanmgtpowercapmax=cursor.fetchall()
	cursor.execute('SELECT wlanmgtpowercapmin, count(wlanmgtpowercapmin) FROM dwccincoming GROUP BY wlanmgtpowercapmin ORDER BY count(wlanmgtpowercapmin) DESC limit 5;')
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
	cursor.execute('SELECT wlanmgtssid, count(wlanmgtssid) FROM dwccincoming GROUP BY wlanmgtssid ORDER BY count(wlanmgtssid) DESC limit 15;')
	wlanmgtssid=cursor.fetchall()
	cursor.execute('SELECT wlanmgtssid, count(wlanmgtssid) FROM dwccap GROUP BY wlanmgtssid ORDER BY count(wlanmgtssid) DESC limit 15;')
	wlanmgtssidap=cursor.fetchall()
	cursor.execute('SELECT wlansaconverted, count(wlansaconverted) FROM dwccap GROUP BY wlansaconverted ORDER BY count(wlansaconverted) DESC limit 15;')
	apmaker=cursor.fetchall()
	cursor.execute('SELECT wlanradiochannel, count(wlanradiochannel) FROM dwccap GROUP BY wlanradiochannel ORDER BY count(wlanradiochannel) DESC limit 15;')
	channelgroupap=cursor.fetchall()
	cursor.execute('SELECT COUNT(*)FROM dwccincoming;')
	numberofclient=cursor.fetchone()[0]
	cursor.execute('SELECT COUNT(*)FROM dwccap;')
	numberofap=cursor.fetchone()[0]
	print "Total number of clients found to support Sounding Dimensions of 1 = ", soundingdimensions0
	print "Total number of clients found to support Sounding Dimensions of 0 = ", soundingdimensions1
	print "Total number of clients found to support Sounding Dimensions of 3 = ", soundingdimensions3


	labelswlanmgtpowercapmax = []
	valueswlanmgtpowercapmax = []
	for i in wlanmgtpowercapmax:
		labelswlanmgtpowercapmax.append(str(i[0]))
		valueswlanmgtpowercapmax.append(i[1])

	
	labelswlanmgtpowercapmin = []
	valueswlanmgtpowercapmin = []
	for i in wlanmgtpowercapmin:
		labelswlanmgtpowercapmin.append(str(i[0]))
		valueswlanmgtpowercapmin.append(i[1])

	
	labelswlanmgtvhtcapabilitiesmaxmpdulength = []
	valueswlanmgtvhtcapabilitiesmaxmpdulength = []
	for i in wlanmgtvhtcapabilitiesmaxmpdulength:
		labelswlanmgtvhtcapabilitiesmaxmpdulength.append(str(i[0]))
		valueswlanmgtvhtcapabilitiesmaxmpdulength.append(i[1])

	
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
		
	labelswlanmgtssid = []
	valueswlanmgtssid = []
	for i in wlanmgtssid:
		labelswlanmgtssid.append(str(i[0]))
		valueswlanmgtssid.append(i[1])

	labelswlanmgtssidap = []
	valueswlanmgtssidap = []
	for i in wlanmgtssidap:
		labelswlanmgtssidap.append(str(i[0]))
		valueswlanmgtssidap.append(i[1])
		
	labelsapmaker = []
	valuesapmaker= []
	for i in apmaker:
		labelsapmaker.append(str(i[0]))
		valuesapmaker.append(i[1])
		
	labelschannelgroupap = []
	valueschannelgroupap = []
	for i in channelgroupap:
		labelschannelgroupap.append(str(i[0]))
		valueschannelgroupap.append(i[1])
		
	figclient = {
  "data": [
    {
      "values": valuesdevicemaker,
      "labels": labelsdevicemaker,
      "domain":{'x': [.2, .49],
              'y': [0, .32]},
      "textinfo": "value+percent",
      "hoverinfo":"label+percent",
      "type": "pie"
    },
    {
      "values": valueschannelgroup,
      "labels": labelschannelgroup,
      "textposition":"inside",
      "domain": {'x': [.2, .49],
             'y': [.33, .62]},
      "textinfo": "value+percent",
      "hoverinfo":"label+percent",
      "type": "pie"
    },
	{
      "values": valueswlanmgtssid,
      "labels": labelswlanmgtssid,
      "textposition":"inside",
      "domain": {'x': [.2, .49],
               'y': [.63, 1]},
      "textinfo": "value+percent",
      "hoverinfo":"label+percent",
      "type": "pie"
    },
	{
      "values": valueswlanmgtpowercapmax,
      "labels": labelswlanmgtpowercapmax,
      "textposition":"inside",
      "domain": {'x': [.50, .98],
             'y': [0, .32]},
      "textinfo": "value+percent",
      "hoverinfo":"label+percent",
      "type": "pie"
    },
	{
      "values": valueswlanmgtpowercapmin,
      "labels": labelswlanmgtpowercapmin,
      "textposition":"inside",
      "domain": {'x': [.50, .98],
             'y': [.33, .62]},
      "textinfo": "value+percent",
      "hoverinfo":"label+percent",
      "type": "pie"
    },
	{
      "values": valueswlanmgtvhtcapabilitiesmaxmpdulength,
      "labels": labelswlanmgtvhtcapabilitiesmaxmpdulength,
      "textposition":"inside",
      "domain": {'x': [.50, .98],
             'y': [.63, 1]},
      "textinfo": "value+percent",
      "hoverinfo":"label+percent",
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
                "text": "MAC vendor client",
                "x": -0.0007575757575757625,
                "y": 0.13726993865030673
            },
            {
                "font": {
                    "size": 20
                },
                "showarrow": False,
                "text": "Channel",
                "x": 0.06969696969696992,
                "y": 0.4924846625766871
            },
            {
                "font": {
                    "size": 20
                },
                "showarrow": False,
                "text": "SSID connected to (top15)",
                "x": -0.04924242424242414,
                "y": 0.8719325153374236
            },
			{
                "font": {
                    "size": 20
                },
                "showarrow": False,
                "text": "power max (top5)",
                "x": 0.9666666666666668,
                "y": 0.12500000000000022
            },
			{
                "font": {
                    "size": 20
                },
                "showarrow": False,
                "text": "power min (top5)",
                "x": 0.9681818181818181,
                "y": 0.48773006134969354
            },
			{
                "font": {
                    "size": 20
                },
                "showarrow": False,
                "text": "Maximum MPDU Length in bytes",
                "x": 1.0916666666666668,
                "y": 0.8489263803680986
            }
        ]
    }
}
	clientchart = plotly.offline.plot(figclient, include_plotlyjs=False, output_type='div')

	
	figap = {
  "data": [
    {
      "values": valueswlanmgtssidap,
      "labels": labelswlanmgtssidap,
      "domain":{'x': [.30, .60],
              'y': [0, .49]},
      "textinfo": "value+percent",
      "hoverinfo":"label+percent",
      "type": "pie"
    },
    {
      "values": valuesapmaker,
      "labels": labelsapmaker,
      "textposition":"inside",
      "domain": {'x': [0, .49],
             'y': [.50, 1]},
      "textinfo": "value+percent",
      "hoverinfo":"label+percent",
      "type": "pie"
    },
	{
      "values": valueschannelgroupap,
      "labels": labelschannelgroupap,
      "textposition":"inside",
      "domain": {'x': [.50, 1],
               'y': [.50, 1]},
      "textinfo": "value+percent",
      "hoverinfo":"label+percent",
      "type": "pie"
    }],

  "layout": {
        "title":"AP info",
		"showlegend": False,
        "annotations": [
            {
                "font": {
                    "size": 20
                },
                "showarrow": False,
                "text": "MAC vendor AP (top15)",
                "x": -0.009848484848484853,
                "y": 0.7875766871165644
            },
            {
                "font": {
                    "size": 20
                },
                "showarrow": False,
                "text": "Channel AP found on(top15)",
                "x": 1.04469696969697,
                "y": 0.80920245398773
            },
            {
                "font": {
                    "size": 20
                },
                "showarrow": False,
                "text": "APs per SSID (top15)",
                "x": 0.1803030303030304,
                "y": 0.21702453987730075
            }
        ]
    }
}
	apchart = plotly.offline.plot(figap, include_plotlyjs=False, output_type='div')
	
	
	f = open('/var/www/html/display.html','w')
	f.write("""
<html>
<head>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
<p>
<table>
<caption>Client supported info</caption>
<tr>
<th>Description</th>
<th>Number of clients that support it</th>
<th>Description</th>
<th>Number of clients that support it</th>
</tr>
<tr>
<td>5 ghz clients</td>
<td>""" + str(n5ghzclientcount) + """</td>
<td>2 ghz clients</td>
<td>""" + str(n2ghzclientcount) + """</td>
</tr>
<tr>
<td>802.11k</td>
<td>""" + str(wlanmgtfixedcapabilitiesradiomeasurement) + """</td>
<td>802.11w</td>
<td>""" + str(n80211wsupport) + """</td>
</tr>
<tr>
<td>BSS Transition/802.11r/FT</td>
<td>""" + str(b19supportcount) + """</td>
<td>interworking/802.11u</td>
<td>""" + str(n80211usupport) + """</td>
</tr>

<tr>
<td>support short Guard Interval 80mhz channel in 5ghz</td>
<td>""" + str(ngi80mhzsupportcount) + """</td>
<td>short Guard Interval 160mhz channel in 5ghz</td>
<td>""" + str(ngi160mhzsupportcount) + """</td>
</tr>

<tr>
<td>QOS map</td>
<td>""" + str(qosmapsupport) + """</td>
<td>wnm notification</td>
<td>""" + str(wnmsupport) + """</td>
</tr>

<tr>
<td>recive frames from mu-mino AP</td>
<td>""" + str(wlanmgtvhtcapabilitiesmubeamformee) + """</td>
<td>send frames to mu-mino AP</td>
<td>""" + str(wlanmgtvhtcapabilitiesmubeamformer) + """</td>
</tr>

<tr>
<td>recive frames from single user beamforming AP</td>
<td>""" + str(wlanmgtvhtcapabilitiessubeamformee) + """</td>
<td>send frames from single user beamforming AP</td>
<td>""" + str(wlanmgtvhtcapabilitiessubeamformer) + """</td>
</tr>

<tr>
<td>802.11h/dfs channels *only show on 5ghz clients</td>
<td>""" + str(wlanmgtfixedcapabilitiesspecman) + """</td>
<td>160hmz contiguous only</td>
<td>""" + str(wlanmgtvhtcapabilitiessupportedchanwidthset1) + """</td>
</tr>

<tr>
<td>160hmz contiguous and 80+80</td>
<td>""" + str(wlanmgtvhtcapabilitiessupportedchanwidthset2) + """</td>
<td>receive LDPC-encoded frames</td>
<td>""" + str(wlanmgtvhtcapabilitiesrxldpc) + """</td>
</tr>

<tr>
<td>Tansmission of STBC-coded frames</td>
<td>""" + str(wlanmgtvhtcapabilitiestxstbc) + """</td>
<td>On-demand beacon realted to 802.11p</td>
<td>""" + str(wlanmgtextcapb1) + """</td>
</tr>

<tr>
<td>Extended Channel Switching</td>
<td>""" + str(wlanmgtextcapb2) + """</td>
<td>WAVE indication this is 802.11p</td>
<td>""" + str(wlanmgtextcapb3) + """</td>
</tr>

<tr>
<td>PSMP Capability</td>
<td>""" + str(wlanmgtextcapb4) + """</td>
<td>Scheduled PSMP</td>
<td>""" + str(wlanmgtextcapb6) + """</td>
</tr>

<tr>
<td>Diagnostic Report</td>
<td>""" + str(wlanmgtextcapb8) + """</td>
<td>Multicast Diagnostics</td>
<td>""" + str(wlanmgtextcapb9) + """</td>
</tr>

<tr>
<td>Orthogonal Frequency-Division Multiplexing OFDM</td>
<td>""" + str(radiotapchannelflagsofdm) + """</td>
<td>Location Tracking</td>
<td>""" + str(wlanmgtextcapb10) + """</td>
</tr>

<tr>
<td>Flexible Multicast Service</td>
<td>""" + str(wlanmgtextcapb11) + """</td>
<td>Proxy ARP in 802.11-2012</td>
<td>""" + str(wlanmgtextcapb12) + """</td>
</tr>

<tr>
<td>Collocated Interference Reporting</td>
<td>""" + str(wlanmgtextcapb13) + """</td>
<td>Civic Location</td>
<td>""" + str(wlanmgtextcapb14) + """</td>
</tr>

<tr>
<td>Geospatial Location</td>
<td>""" + str(wlanmgtextcapb15) + """</td>
<td>TFS</td>
<td>""" + str(wlanmgtextcapb16) + """</td>
</tr>

<tr>
<td>WNM-Sleep Mode</td>
<td>""" + str(wlanmgtextcapb17) + """</td>
<td>TIM Broadcast</td>
<td>""" + str(wlanmgtextcapb18) + """</td>
</tr>

<tr>
<td>QoS Traffic Capability</td>
<td>""" + str(wlanmgtextcapb20) + """</td>
<td>AC Station Count</td>
<td>""" + str(wlanmgtextcapb21) + """</td>
</tr>

<tr>
<td>Multiple BSSID</td>
<td>""" + str(wlanmgtextcapb22) + """</td>
<td>Timing Measurement</td>
<td>""" + str(wlanmgtextcapb23) + """</td>
</tr>

<tr>
<td>Channel Usage</td>
<td>""" + str(wlanmgtextcapb24) + """</td>
<td>SSID List</td>
<td>""" + str(wlanmgtextcapb25) + """</td>
</tr>

<tr>
<td>DMS</td>
<td>""" + str(wlanmgtextcapb26) + """</td>
<td>UTC TSF Offset</td>
<td>""" + str(wlanmgtextcapb27) + """</td>
</tr>

<tr>
<td>Peer U-APSD Buffer STA Support</td>
<td>""" + str(wlanmgtextcapb28) + """</td>
<td>TDLS Peer PSM Support</td>
<td>""" + str(wlanmgtextcapb29) + """</td>
</tr>

<tr>
<td>TDLS channel switching</td>
<td>""" + str(wlanmgtextcapb30) + """</td>
<td>EBR</td>
<td>""" + str(wlanmgtextcapb33) + """</td>
</tr>

<tr>
<td>SSPN Interface</td>
<td>""" + str(wlanmgtextcapb34) + """</td>




</table>

<table>
<caption>Stats</caption>
<tr>
<th>Description</th>
<th>Number</th>
</tr>
<tr>
<td>number of clients found in the database</td>
<td>""" + str(numberofclient) + """</td>

</tr>
<tr>
<td>number of APs found in the database</td>
<td>""" + str(numberofap) + """</td>

</tr>
</table>
</p>
""" + str(clientchart) + """
""" + str(apchart) + """
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
	cursor.execute("UPDATE dwccap SET wlanmgtssid = 'SSIDnotfound' WHERE wlanmgtssid is null or wlanmgtssid = '';")
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
						regexhostname = re.compile(r'^[A-Za-z0-9_.]+')
						hostnameonly = regexhostname.findall(fname)
						regexyear = re.compile(r'([0-9]{4}\-[0-9]{2}\-[0-9]{2}\_[0-9]{2}\.[0-9]{2}\.[0-9]{2})')
						timestamp = regexyear.findall(fname)
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
						subprocess.call("""tshark -r """ + pcapfile + """   -R "wlan.fc.type_subtype == 0x0 or wlan.fc.type_subtype == 0x2 or wlan.fc.type_subtype == 0x4" -2 -T fields -e wlan.sa -e wlan.bssid \
-e wlan_radio.signal_dbm -E separator=+ | sed 's/$/+"""+ str(hostnameonly) + """+"""+ str(timestamp) +"""/' >> """+ tmppath + """dwcc-heatmap.csv""", shell=True)
						subprocess.call('tshark -r ' + pcapfile + '   -R "wlan.fc.type_subtype == 0x4" -2 -T fields -e wlan.sa -e wlan.bssid -e radiotap.channel.freq -e wlan_mgt.extcap.b19 -e wlan.fc.protected \
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
-e wlan_mgt.vht.mcsset.txmcsmap.ss1 -e wlan_mgt.vht.mcsset.txmcsmap.ss2 -e wlan_mgt.vht.mcsset.txmcsmap.ss3 -e wlan_mgt.vht.mcsset.txmcsmap.ss4 \
-E separator=+ >> ' + tmppath + 'dwcc-probe.csv', shell=True)
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
	
	
	
def macaddressconverterprobe():
	for i in range(50):
		p = manuf.MacParser(update=True)
		cursor.execute("""SELECT wlansa from dwccincomingprobe WHERE wlansaconverted IS NULL OR wlansaconverted = '' limit 1;""")
		mactochange = cursor.fetchone()
	
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
			cursor.execute("UPDATE dwccap SET wlansaconverted = "+ `changedmacstr` +" WHERE wlanbssid  = "+ `mactochangestr` +"   ;")
#			macaddressconverterap()
	conn.commit()
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

	csvfileprobe = '/data/tmp/dwcc-probe.csv'
#	#this will check for the CSV file, If it is found then import it into the database. If no CSV is found then it move on
	if os.path.isfile(csvfileprobe) and os.access(csvfileprobe, os.R_OK):
		print "probe csv found adding to db"
		subprocess.call("""awk '!seen[$0]++' /data/tmp/dwcc-probe.csv | sed -e 's/ /-/g' -e 's/[<>"^()@#&!$.,*]//g' -e "s/'//g" -e '/^$/d' -e 's/[][]//g' -e 's/[-_]//g' >> /data/tmp/temp-dwcc-probe.csv""", shell=True)
		os.remove("/data/tmp/dwcc-probe.csv")
		os.rename("/data/tmp/temp-dwcc-probe.csv", "/data/tmp/dwcc-probe.csv")
		csv_probe = csv.reader(file(csvfileprobe), delimiter='+')
		for rowprobe in csv_probe:
			conn.execute('INSERT INTO dwccincomingprobe (wlansa, wlanbssid, radiotapchannelfreq, wlanmgtextcapb19, wlanfcprotected, \
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
wlanmgtvhtmcssetrxmcsmapss4, wlanmgtvhtmcssettxmcsmapss1, wlanmgtvhtmcssettxmcsmapss2, wlanmgtvhtmcssettxmcsmapss3, wlanmgtvhtmcssettxmcsmapss4)' \
'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', rowprobe)
		conn.commit()
#This will remove the file after it is added to the db
		os.remove(csvfileprobe)
		print "done with dbupdate for probe waiting for next run"
	else:
		print"csv probe not found will retry"
		
		
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
		
	csvheatmap = '/data/tmp/dwcc-heatmap.csv'
	#this will check for the CSV file, If it is found then import it into the database. If no CSV is found then it move on
	if os.path.isfile(csvheatmap) and os.access(csvheatmap, os.R_OK):
		print "heatmap csv found adding to db"
		subprocess.call("""cat /data/tmp/dwcc-heatmap.csv | awk '!seen[$0]++' | sed -e 's/ //g' -e 's/[<>"^()@#&!$.,]//g' -e "s/'//g" -e '/^$/d' -e 's/[][]//g' -e 's/[-_]//g' -e 's/...$/000/' >> /data/tmp/temp-dwcc-heatmap.csv """, shell=True)
		os.remove("/data/tmp/dwcc-heatmap.csv")
		os.rename("/data/tmp/temp-dwcc-heatmap.csv", "/data/tmp/dwcc-heatmap.csv")
		csv_heatmap = csv.reader(file(csvheatmap), delimiter='+')
		for rowheatmap in csv_heatmap:
			conn.execute('INSERT INTO dwccheatmapincoming (wlansa, wlanbssid, wlanradiosignaldbm, node, timestamp)' 'VALUES (?,?,?,?,?)', rowheatmap)
		conn.commit()
#This will remove the file after it is added to the db
		os.remove(csvheatmap)
		print "done with dbupdate for heatmap waiting for next run"
	else:
		print"csv heatmap not found will retry"
		
		
		
		
def heatmapprep():
	cursor.execute('''INSERT INTO dwccheatmapreporting (wlansa, timestamp, sigfromnode1)
SELECT wlansa,  timestamp, avg(wlanradiosignaldbm) as sigfromnode1 
FROM dwccheatmapincoming  
where node = 'node1' and addedtoreporting is null
GROUP BY wlansa, timestamp ;''')
	cursor.execute('''UPDATE dwccheatmapincoming SET addedtoreporting = '1' WHERE addedtoreporting is null;''')
	conn.commit()
	
def heatmapping():
	cursor.execute('''SELECT max (timestamp) FROM dwccheatmapreporting GROUP BY timestamp limit 1;''')
	timestamptomap = cursor.fetchone()
	timestamptomap = ''.join(c for c in timestamptomap if c not in string.punctuation)
	cursor.execute("""select * from dwccheatmapreporting where timestamp = """+str(timestamptomap)+""";""")
	clientstomap  = cursor.fetchall()
	
	cursor.execute("""select * from dwccheatmapreporting where timestamp = """+str(timestamptomap)+""";""")
	clientstomap  = cursor.fetchall()
	
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

	cursor.execute('''CREATE TABLE if not exists dwccincomingprobe
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
	cursor.execute('''CREATE TABLE if not exists dwccheatmapincoming
(ID INTEGER PRIMARY KEY autoincrement NOT NULL,
wlansa char(50),
wlanbssid char(50),
wlanradiosignaldbm char(200),
node char(50),
timestamp char(50),
wlansaconverted char(200),
addedtoreporting char(50));''')
	conn.commit()
	
	cursor.execute('''CREATE TABLE if not exists dwccheatmapreporting (
	ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	wlansa char ( 50 ),
	timestamp	char ( 50 ),
	sigfromnode1	char ( 50 ),
	sigfromnode2	char ( 50 ),
	sigfromnode3	char ( 50 ),
	sigfromnode4	char ( 50 ),
	sigfromnode5	char ( 50 ),
	sigfromnode6	char ( 50 ),
	sigfromnode7	char ( 50 ),
	sigfromnode8	char ( 50 ),
	sigfromnode9	char ( 50 ),
	sigfromnode10	char ( 50 ));''')
	conn.commit()

	cursor.execute('''CREATE TABLE if not exists dwccheatmapnodes
(nodename char(50) NOT NULL,
xposition char(50),
yposition char(50),
PRIMARY KEY(`nodename`));''')
	conn.commit()
	
	cursor.execute('''INSERT OR IGNORE INTO dwccheatmapnodes VALUES('node1', '.25', '.25' ),('node2', '.25', '.75' ),('node3', '.75', '.25' ),('node4', '.75', '.75' ),('node5', '.50', '.50' );''')
	conn.commit()
start()
