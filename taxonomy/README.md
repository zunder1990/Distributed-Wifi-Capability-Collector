The script taxonomy.py will load the PCAPS found here https://github.com/NetworkDeviceTaxonomy/wifi_taxonomy/tree/master/testdata/pcaps It will run tshark on them and make a CSV of the output. A copy of those csv can be found in this folder. The script will then load the csv into the dwcc database.

Usage for fresh install or database rebuild = You dont need to download the pcaps. You can simple run the script in this currect folder and it will load the CSV from this folder into the database. 
