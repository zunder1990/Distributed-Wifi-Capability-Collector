#!/bin/bash
apt-get install python-dev tcpdump
apt-get install python3-dev
apt-get install libffi-dev
apt-get install libffi-dev libssl-dev
apt-get install python3-pip
pip3 install --upgrade setuptools
pip3 install pysftp
pip3 install enum
mkdir -p /root/Distributed-Wifi-Capability-Collector
touch /root/Distributed-Wifi-Capability-Collector/dwcc.log
