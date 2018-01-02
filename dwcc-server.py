import sys
import os
import logging
import MySQLdb


mydb = MySQLdb.connect(host='localhost',
    user='dwcc',
    passwd='dwcc',
    db='dwcc')
	
	
def start():
	dedup()

	 

def dedup():
			cursor = mydb.cursor()
			stmt = """USE dwcc; DELETE FROM dwcc  WHERE id IN (SELECT * FROM (SELECT id FROM dwcc GROUP BY `wlan.sa` HAVING (COUNT(*) > 1)) AS A);"""
			cursor.execute(stmt)



	

	
start()


