#!/usr/bin/python
import sys
import sqlite3
import time
import plotly



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


def start():
	while True:
		try:
			probecharting()
			charting()
			time.sleep(30)#seconds
		except KeyboardInterrupt: sys.exit()


def probecharting():
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb19 = 1;')
    b19supportcount = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiesshort80 = 1;')
    ngi80mhzsupportcount = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiesshort160 = 1;')
    ngi160mhzsupportcount = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE radiotapchannelflags5ghz = 1;')
    n5ghzclientcount = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE radiotapchannelflags2ghz = 1;')
    n2ghzclientcount = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtrsncapabilitiesmfpc = 1;')
    n80211wsupport = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb31 = 1;')
    n80211usupport = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb32 = 1;')
    qosmapsupport = cursor.fetchone()[0]
    cursor.execute(
        'SELECT wlansaconverted, count(wlansaconverted) FROM dwccincomingprobe GROUP BY wlansaconverted ORDER BY count(wlansaconverted) DESC limit 10;')
    devicemaker = cursor.fetchall()
    cursor.execute(
        'SELECT wlanradiochannel, count(wlanradiochannel) FROM dwccincomingprobe GROUP BY wlanradiochannel ORDER BY count(wlanradiochannel) DESC limit 10;')
    channelgroup = cursor.fetchall()
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb46 = 1;')
    wnmsupport = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiessoundingdimensions = 0;')
    soundingdimensions0 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiessoundingdimensions = 1;')
    soundingdimensions1 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiessoundingdimensions = 3;')
    soundingdimensions3 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiesmubeamformee = 1;')
    wlanmgtvhtcapabilitiesmubeamformee = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiesmubeamformer = 1;')
    wlanmgtvhtcapabilitiesmubeamformer = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiessubeamformee = 1;')
    wlanmgtvhtcapabilitiessubeamformee = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiessubeamformer = 1;')
    wlanmgtvhtcapabilitiessubeamformer = cursor.fetchone()[0]
    cursor.execute(
        'SELECT wlanmgtpowercapmax, count(wlanmgtpowercapmax) FROM dwccincomingprobe GROUP BY wlanmgtpowercapmax ORDER BY count(wlanmgtpowercapmax) DESC limit 5;')
    wlanmgtpowercapmax = cursor.fetchall()
    cursor.execute(
        'SELECT wlanmgtpowercapmin, count(wlanmgtpowercapmin) FROM dwccincomingprobe GROUP BY wlanmgtpowercapmin ORDER BY count(wlanmgtpowercapmin) DESC limit 5;')
    wlanmgtpowercapmin = cursor.fetchall()
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtfixedcapabilitiesspecman = 1;')
    wlanmgtfixedcapabilitiesspecman = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtfixedcapabilitiesradiomeasurement = 1;')
    wlanmgtfixedcapabilitiesradiomeasurement = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiessupportedchanwidthset = 1;')
    wlanmgtvhtcapabilitiessupportedchanwidthset1 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiessupportedchanwidthset = 2;')
    wlanmgtvhtcapabilitiessupportedchanwidthset2 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiesrxldpc = 1;')
    wlanmgtvhtcapabilitiesrxldpc = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtvhtcapabilitiestxstbc = 1;')
    wlanmgtvhtcapabilitiestxstbc = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb1 = 1;')
    wlanmgtextcapb1 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb2 = 1;')
    wlanmgtextcapb2 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb3 = 1;')
    wlanmgtextcapb3 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb4 = 1;')
    wlanmgtextcapb4 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb6 = 1;')
    wlanmgtextcapb6 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb8 = 1;')
    wlanmgtextcapb8 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb9 = 1;')
    wlanmgtextcapb9 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb10 = 1;')
    wlanmgtextcapb10 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb11 = 1;')
    wlanmgtextcapb11 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb12 = 1;')
    wlanmgtextcapb12 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb13 = 1;')
    wlanmgtextcapb13 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb14 = 1;')
    wlanmgtextcapb14 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb15 = 1;')
    wlanmgtextcapb15 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb16 = 1;')
    wlanmgtextcapb16 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb17 = 1;')
    wlanmgtextcapb17 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb18 = 1;')
    wlanmgtextcapb18 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb20 = 1;')
    wlanmgtextcapb20 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb21 = 1;')
    wlanmgtextcapb21 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb22 = 1;')
    wlanmgtextcapb22 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb23 = 1;')
    wlanmgtextcapb23 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb24 = 1;')
    wlanmgtextcapb24 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb25 = 1;')
    wlanmgtextcapb25 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb26 = 1;')
    wlanmgtextcapb26 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb27 = 1;')
    wlanmgtextcapb27 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb28 = 1;')
    wlanmgtextcapb28 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb29 = 1;')
    wlanmgtextcapb29 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb30 = 1;')
    wlanmgtextcapb30 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb33 = 1;')
    wlanmgtextcapb33 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE wlanmgtextcapb34 = 1;')
    wlanmgtextcapb34 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincomingprobe WHERE radiotapchannelflagsofdm = 1;')
    radiotapchannelflagsofdm = cursor.fetchone()[0]
    cursor.execute(
        'SELECT wlanmgtvhtcapabilitiesmaxmpdulength, count(wlanmgtvhtcapabilitiesmaxmpdulength) FROM dwccincomingprobe GROUP BY wlanmgtvhtcapabilitiesmaxmpdulength ORDER BY count(wlanmgtvhtcapabilitiesmaxmpdulength) DESC;')
    wlanmgtvhtcapabilitiesmaxmpdulength = cursor.fetchall()
    cursor.execute(
        'SELECT wlanmgtssid, count(wlanmgtssid) FROM dwccincomingprobe GROUP BY wlanmgtssid ORDER BY count(wlanmgtssid) DESC limit 15;')
    wlanmgtssid = cursor.fetchall()
    cursor.execute('SELECT COUNT(*)FROM dwccincomingprobe;')
    numberofclient = cursor.fetchone()[0]
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

    figprobe = {
        "data": [
            {
                "values": valuesdevicemaker,
                "labels": labelsdevicemaker,
                "domain": {'x': [.2, .49],
                           'y': [0, .32]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valueschannelgroup,
                "labels": labelschannelgroup,
                "textposition": "inside",
                "domain": {'x': [.2, .49],
                           'y': [.33, .62]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valueswlanmgtssid,
                "labels": labelswlanmgtssid,
                "textposition": "inside",
                "domain": {'x': [.2, .49],
                           'y': [.63, 1]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valueswlanmgtpowercapmax,
                "labels": labelswlanmgtpowercapmax,
                "textposition": "inside",
                "domain": {'x': [.50, .98],
                           'y': [0, .32]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valueswlanmgtpowercapmin,
                "labels": labelswlanmgtpowercapmin,
                "textposition": "inside",
                "domain": {'x': [.50, .98],
                           'y': [.33, .62]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valueswlanmgtvhtcapabilitiesmaxmpdulength,
                "labels": labelswlanmgtvhtcapabilitiesmaxmpdulength,
                "textposition": "inside",
                "domain": {'x': [.50, .98],
                           'y': [.63, 1]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            }],

        "layout": {
            "title": "Client info from probes",
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
    probechart = plotly.offline.plot(figprobe, include_plotlyjs=False, output_type='div')
    f = open('/var/www/html/display-probe.html', 'w')
    f.write("""
<html>
<head>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
<p>
<table>
<caption>Client supported info based on probes</caption>
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
<td>number of clients found in the database based on probes</td>
<td>""" + str(numberofclient) + """</td>
</tr>
</table>

</p>
""" + str(probechart) + """
</body>
</html>
""")
    f.close()


def charting():
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb19 = 1;')
    b19supportcount = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesshort80 = 1;')
    ngi80mhzsupportcount = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesshort160 = 1;')
    ngi160mhzsupportcount = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE radiotapchannelflags5ghz = 1;')
    n5ghzclientcount = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE radiotapchannelflags2ghz = 1;')
    n2ghzclientcount = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtrsncapabilitiesmfpc = 1;')
    n80211wsupport = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb31 = 1;')
    n80211usupport = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb32 = 1;')
    qosmapsupport = cursor.fetchone()[0]
    cursor.execute(
        'SELECT wlansaconverted, count(wlansaconverted) FROM dwccincoming GROUP BY wlansaconverted ORDER BY count(wlansaconverted) DESC limit 10;')
    devicemaker = cursor.fetchall()
    cursor.execute(
        'SELECT wlanradiochannel, count(wlanradiochannel) FROM dwccincoming GROUP BY wlanradiochannel ORDER BY count(wlanradiochannel) DESC limit 10;')
    channelgroup = cursor.fetchall()
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb46 = 1;')
    wnmsupport = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessoundingdimensions = 0;')
    soundingdimensions0 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessoundingdimensions = 1;')
    soundingdimensions1 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessoundingdimensions = 3;')
    soundingdimensions3 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesmubeamformee = 1;')
    wlanmgtvhtcapabilitiesmubeamformee = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesmubeamformer = 1;')
    wlanmgtvhtcapabilitiesmubeamformer = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessubeamformee = 1;')
    wlanmgtvhtcapabilitiessubeamformee = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessubeamformer = 1;')
    wlanmgtvhtcapabilitiessubeamformer = cursor.fetchone()[0]
    cursor.execute(
        'SELECT wlanmgtpowercapmax, count(wlanmgtpowercapmax) FROM dwccincoming GROUP BY wlanmgtpowercapmax ORDER BY count(wlanmgtpowercapmax) DESC limit 5;')
    wlanmgtpowercapmax = cursor.fetchall()
    cursor.execute(
        'SELECT wlanmgtpowercapmin, count(wlanmgtpowercapmin) FROM dwccincoming GROUP BY wlanmgtpowercapmin ORDER BY count(wlanmgtpowercapmin) DESC limit 5;')
    wlanmgtpowercapmin = cursor.fetchall()
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtfixedcapabilitiesspecman = 1;')
    wlanmgtfixedcapabilitiesspecman = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtfixedcapabilitiesradiomeasurement = 1;')
    wlanmgtfixedcapabilitiesradiomeasurement = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessupportedchanwidthset = 1;')
    wlanmgtvhtcapabilitiessupportedchanwidthset1 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiessupportedchanwidthset = 2;')
    wlanmgtvhtcapabilitiessupportedchanwidthset2 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiesrxldpc = 1;')
    wlanmgtvhtcapabilitiesrxldpc = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtvhtcapabilitiestxstbc = 1;')
    wlanmgtvhtcapabilitiestxstbc = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb1 = 1;')
    wlanmgtextcapb1 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb2 = 1;')
    wlanmgtextcapb2 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb3 = 1;')
    wlanmgtextcapb3 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb4 = 1;')
    wlanmgtextcapb4 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb6 = 1;')
    wlanmgtextcapb6 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb8 = 1;')
    wlanmgtextcapb8 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb9 = 1;')
    wlanmgtextcapb9 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb10 = 1;')
    wlanmgtextcapb10 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb11 = 1;')
    wlanmgtextcapb11 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb12 = 1;')
    wlanmgtextcapb12 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb13 = 1;')
    wlanmgtextcapb13 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb14 = 1;')
    wlanmgtextcapb14 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb15 = 1;')
    wlanmgtextcapb15 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb16 = 1;')
    wlanmgtextcapb16 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb17 = 1;')
    wlanmgtextcapb17 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb18 = 1;')
    wlanmgtextcapb18 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb20 = 1;')
    wlanmgtextcapb20 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb21 = 1;')
    wlanmgtextcapb21 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb22 = 1;')
    wlanmgtextcapb22 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb23 = 1;')
    wlanmgtextcapb23 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb24 = 1;')
    wlanmgtextcapb24 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb25 = 1;')
    wlanmgtextcapb25 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb26 = 1;')
    wlanmgtextcapb26 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb27 = 1;')
    wlanmgtextcapb27 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb28 = 1;')
    wlanmgtextcapb28 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb29 = 1;')
    wlanmgtextcapb29 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb30 = 1;')
    wlanmgtextcapb30 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb33 = 1;')
    wlanmgtextcapb33 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE wlanmgtextcapb34 = 1;')
    wlanmgtextcapb34 = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM dwccincoming WHERE radiotapchannelflagsofdm = 1;')
    radiotapchannelflagsofdm = cursor.fetchone()[0]
    cursor.execute(
        'SELECT wlanmgtvhtcapabilitiesmaxmpdulength, count(wlanmgtvhtcapabilitiesmaxmpdulength) FROM dwccincoming GROUP BY wlanmgtvhtcapabilitiesmaxmpdulength ORDER BY count(wlanmgtvhtcapabilitiesmaxmpdulength) DESC;')
    wlanmgtvhtcapabilitiesmaxmpdulength = cursor.fetchall()
    cursor.execute(
        'SELECT wlanmgtssid, count(wlanmgtssid) FROM dwccincoming GROUP BY wlanmgtssid ORDER BY count(wlanmgtssid) DESC limit 15;')
    wlanmgtssid = cursor.fetchall()
    cursor.execute(
        'SELECT wlanmgtssid, count(wlanmgtssid) FROM dwccap GROUP BY wlanmgtssid ORDER BY count(wlanmgtssid) DESC limit 15;')
    wlanmgtssidap = cursor.fetchall()
    cursor.execute(
        'SELECT wlansaconverted, count(wlansaconverted) FROM dwccap GROUP BY wlansaconverted ORDER BY count(wlansaconverted) DESC limit 15;')
    apmaker = cursor.fetchall()
    cursor.execute(
        'SELECT wlanradiochannel, count(wlanradiochannel) FROM dwccap GROUP BY wlanradiochannel ORDER BY count(wlanradiochannel) DESC limit 15;')
    channelgroupap = cursor.fetchall()
    cursor.execute('SELECT COUNT(*)FROM dwccincoming;')
    numberofclient = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*)FROM dwccap;')
    numberofap = cursor.fetchone()[0]
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
    valuesapmaker = []
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
                "domain": {'x': [.2, .49],
                           'y': [0, .32]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valueschannelgroup,
                "labels": labelschannelgroup,
                "textposition": "inside",
                "domain": {'x': [.2, .49],
                           'y': [.33, .62]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valueswlanmgtssid,
                "labels": labelswlanmgtssid,
                "textposition": "inside",
                "domain": {'x': [.2, .49],
                           'y': [.63, 1]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valueswlanmgtpowercapmax,
                "labels": labelswlanmgtpowercapmax,
                "textposition": "inside",
                "domain": {'x': [.50, .98],
                           'y': [0, .32]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valueswlanmgtpowercapmin,
                "labels": labelswlanmgtpowercapmin,
                "textposition": "inside",
                "domain": {'x': [.50, .98],
                           'y': [.33, .62]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valueswlanmgtvhtcapabilitiesmaxmpdulength,
                "labels": labelswlanmgtvhtcapabilitiesmaxmpdulength,
                "textposition": "inside",
                "domain": {'x': [.50, .98],
                           'y': [.63, 1]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            }],

        "layout": {
            "title": "Client info",
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
                "domain": {'x': [.30, .60],
                           'y': [0, .49]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valuesapmaker,
                "labels": labelsapmaker,
                "textposition": "inside",
                "domain": {'x': [0, .49],
                           'y': [.50, 1]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            },
            {
                "values": valueschannelgroupap,
                "labels": labelschannelgroupap,
                "textposition": "inside",
                "domain": {'x': [.50, 1],
                           'y': [.50, 1]},
                "textinfo": "value+percent",
                "hoverinfo": "label+percent",
                "type": "pie"
            }],

        "layout": {
            "title": "AP info",
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

    f = open('/var/www/html/display.html', 'w')
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

start()