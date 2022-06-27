### This is a Python script that will perform STIG compliance checks for the Cisco IOS XE NDM V2R2 checklist and fill out a CKL with the results.
###
### This script was created by Alex Dean (alex.d.dean3.ctr@us.navy.mil, NREN NOC). If you have any questions, issues, suggestions, or would like to contribute, please
### 	don't hesitate to reach out!
###
### This script was made because there are currently no DISA provided tools for automating Cisco IOS XE switch STIGs.
###
### This script requires either a) SSH connectivity and a credential to the target switch with at least read permissions, or b) a config file that is simply an output of
###		a 'show run' command from the switch. A 'show run all' command will cause issues with this script, so make sure the config file is NOT the ouput of a 'show run all'.
###
import os
import xml.etree.ElementTree as ET
import getpass
from datetime import datetime
from tkinter import filedialog
from pathlib import Path

def getOnlineStatus(): # this function is used to determine if the user wants to use ssh for a live collection or not. THe results of this will determine if the rest of the script will need to look for the multiple output .txt files that would normally be gathered from a live colleciton.
	global onlineStatus
	global offline_mode
	onlineStatus = input("Would you like to use SSH to perform a live collection of switch configs to be STIG'd?\n(If 'no', then you'll be prompted to choose a .txt config file of the switch)\nPlease note that only most, but not all, STIG checks can be completed in 'offline mode'.\nPlease enter 'yes' or 'no': ")
	acceptable_yes_statuses = ["yes","y"]
	acceptable_no_statuses = ["no","n"]

	for word in onlineStatus.split(" "): # this for loop checks to see if the user entered yes or no and sets the offline_mode variable accordingly.
		if word.lower() in acceptable_yes_statuses:
			offline_mode = False

		elif word.lower() in acceptable_no_statuses:
			offline_mode = True

		else:
			print(onlineStatus + " is not a valid option. Please try again.\n") # if user enters anything other than yes/no/y/n, it'll loop back to the question and ask again.
			getOnlineStatus()

getOnlineStatus()

def onlineConfigGather():
	exec(open("paramiko_gather_showrun.py").read())

	global show_run_config
	global snmp_user_config
	global show_version_config
	global show_logging_config

	show_run_config = "show_run.txt"
	snmp_user_config = "show_snmp_user.txt"
	show_version_config = "show_version.txt"
	show_logging_config = "show_logging.txt"
	
if offline_mode == False:

	onlineConfigGather() #if user enters yes, it will perform ssh connections to gather necessary outputs from switch.

elif offline_mode == True:
	# user will be prompted to select a .txt file to use instead of performing live collections using ssh.
	# Note, due to the nature of the checks performed in this script, the only variable that can be accurately used is show_run_config.
	# The other config variables cannot be used because the scope is not narrow enough from just a .txt config file.
	# Therefore, there will be a few STIG checks that cannot be accurately checked for.

	#offline_mode = True

	global show_run_config
	global snmp_user_config
	global show_version_config
	global show_logging_config

	exec(open("create_offline_placeholders.py").read()) # this placeholders python script will create the show_x_.txt files so the few checks that require the seperate show outputs will not error
	# 													  	out. This also allows minimal changes required to accomade the entire script for offline mode.

	config_text = filedialog.askopenfilenames(initialdir="/", title="Select config file (must be .txt)")

	snmp_user_placeholder = "show_snmp_user.txt"
	show_version_placeholder = "show_version.txt"
	show_logging_placeholder = "show_logging.txt"
	print(config_text)
	show_run_config = "".join(config_text)
	print(show_run_config)
	snmp_user_config = "".join(snmp_user_placeholder)
	show_version_config = "".join(show_version_placeholder)
	show_logging_config = "".join(show_logging_placeholder)
	print(show_logging_config)



#xmlfile = "CAML365001-Cisco_IOS_XE_Switch_NDM_STIG-V2R2.ckl" # This is the target CKL file that will be written to as checks are performed.
print("********************************************************************************************************************************************************************************")
print("Please select the CKL to be filled out.\nMake sure to mark all not applicable STIGs as Not Applicable in the CKL BEFORE running this script or you will receive false positives!")
print("********************************************************************************************************************************************************************************")
xmlfile = filedialog.askopenfilenames(initialdir="/", title="Select CKL")
original_xml_filepath = xmlfile
print(xmlfile)

xmlfile = "".join(xmlfile)
print(xmlfile)

# This 'with open' code will read the ckl file that is chosen to see if it has the 'STIG Manager' comment or not. This will be used to determine if the CKL is using STIGMAN format or not.
with open(xmlfile) as myxmlfile:
	readfile = myxmlfile.read()

	if "<!-- STIG Manager" in readfile:
		print("STIGMAN comment found in CKL.")
		ckl_is_from_stigman = True
		ckl_is_from_stigviewer = False

	else:
		ckl_is_from_stigviewer = True
		ckl_is_from_stigman = False

	#for i in range(3):
	#	#print(myxmlfile.readline())
	#	ckl_headers = (myxmlfile.readline())
	#	print(ckl_headers)

		#if "STIG Manager" in ckl_headers:
		#	#print("This ckl looks like it's from STIGMAN.")
		#	ckl_is_from_stigman = True
		#	ckl_is_from_stigviewer = False
		#	break
		#elif "STIG Manager" not in ckl_headers:
		#	#print("This CKL looks like it is NOT from STIGMAN.")
		#	ckl_is_from_stigviewer = True
		#	ckl_is_from_stigman = False
		
if ckl_is_from_stigman:
	print("This CKL looks like it is from STIGMAN.\n\n")
else:
	print("This CKL does NOT look like it is from STIGMAN.\n\n")

tree = ET.parse(xmlfile)
root = tree.getroot()

### END OF CKL SOURCE DETERMINATION ###

# This class contains some important attributes of STIGs. Each vuln ID will have these instance attributes.
class STIG():

	def __init__(self,vuln_id,status,finding_details,comments):
		# instance attributes
		self.vuln_id = vuln_id
		self.status = status
		self.finding_details = finding_details
		self.comments = comments


### List of all instances of STIGs in Cisco IOS XE NCM V2R2 checklist ### *index locations are probably identical on all CKLs since the format is the same
if ckl_is_from_stigviewer:
	V_220518 = STIG(root[1][0][1][0][1].text,root[1][0][1][28].text,root[1][0][1][29].text,root[1][0][1][30].text)
	V_220519 = STIG(root[1][0][2][0][1].text,root[1][0][2][28].text,root[1][0][2][29].text,root[1][0][2][30].text)
	V_220520 = STIG(root[1][0][3][0][1].text,root[1][0][3][28].text,root[1][0][3][29].text,root[1][0][3][30].text)
	V_220521 = STIG(root[1][0][4][0][1].text,root[1][0][4][28].text,root[1][0][4][29].text,root[1][0][4][30].text)
	V_220522 = STIG(root[1][0][5][0][1].text,root[1][0][5][28].text,root[1][0][5][29].text,root[1][0][5][30].text)
	V_220523 = STIG(root[1][0][6][0][1].text,root[1][0][6][28].text,root[1][0][6][29].text,root[1][0][6][30].text)
	V_220524 = STIG(root[1][0][7][0][1].text,root[1][0][7][28].text,root[1][0][7][29].text,root[1][0][7][30].text)
	V_220525 = STIG(root[1][0][8][0][1].text,root[1][0][8][28].text,root[1][0][8][29].text,root[1][0][8][30].text)
	V_220526 = STIG(root[1][0][9][0][1].text,root[1][0][9][28].text,root[1][0][9][29].text,root[1][0][9][30].text)
	V_220527 = STIG(root[1][0][10][0][1].text,root[1][0][10][28].text,root[1][0][10][29].text,root[1][0][10][30].text)
	V_220528 = STIG(root[1][0][11][0][1].text,root[1][0][11][28].text,root[1][0][11][29].text,root[1][0][11][30].text)
	V_220529 = STIG(root[1][0][12][0][1].text,root[1][0][12][28].text,root[1][0][12][29].text,root[1][0][12][30].text)
	V_220530 = STIG(root[1][0][13][0][1].text,root[1][0][13][28].text,root[1][0][13][29].text,root[1][0][13][30].text)
	V_220531 = STIG(root[1][0][14][0][1].text,root[1][0][14][28].text,root[1][0][14][29].text,root[1][0][14][30].text)
	V_220532 = STIG(root[1][0][15][0][1].text,root[1][0][15][28].text,root[1][0][15][29].text,root[1][0][15][30].text)
	V_220533 = STIG(root[1][0][16][0][1].text,root[1][0][16][28].text,root[1][0][16][29].text,root[1][0][16][30].text)
	V_220534 = STIG(root[1][0][17][0][1].text,root[1][0][17][28].text,root[1][0][17][29].text,root[1][0][17][30].text)
	V_220535 = STIG(root[1][0][18][0][1].text,root[1][0][18][29].text,root[1][0][18][30].text,root[1][0][18][31].text)
	V_220536 = STIG(root[1][0][19][0][1].text,root[1][0][19][28].text,root[1][0][19][29].text,root[1][0][19][30].text)
	V_220537 = STIG(root[1][0][20][0][1].text,root[1][0][20][28].text,root[1][0][20][29].text,root[1][0][20][30].text)
	V_220538 = STIG(root[1][0][21][0][1].text,root[1][0][21][28].text,root[1][0][21][29].text,root[1][0][21][30].text)
	V_220539 = STIG(root[1][0][22][0][1].text,root[1][0][22][28].text,root[1][0][22][29].text,root[1][0][22][30].text)
	V_220540 = STIG(root[1][0][23][0][1].text,root[1][0][23][28].text,root[1][0][23][29].text,root[1][0][23][30].text)
	V_220541 = STIG(root[1][0][24][0][1].text,root[1][0][24][28].text,root[1][0][24][29].text,root[1][0][24][30].text)
	V_220542 = STIG(root[1][0][25][0][1].text,root[1][0][25][28].text,root[1][0][25][29].text,root[1][0][25][30].text)
	V_220543 = STIG(root[1][0][26][0][1].text,root[1][0][26][28].text,root[1][0][26][29].text,root[1][0][26][30].text)
	V_220544 = STIG(root[1][0][27][0][1].text,root[1][0][27][28].text,root[1][0][27][29].text,root[1][0][27][30].text)
	V_220545 = STIG(root[1][0][28][0][1].text,root[1][0][28][28].text,root[1][0][28][29].text,root[1][0][28][30].text)
	V_220546 = STIG(root[1][0][29][0][1].text,root[1][0][29][28].text,root[1][0][29][29].text,root[1][0][29][30].text)
	V_220547 = STIG(root[1][0][30][0][1].text,root[1][0][30][28].text,root[1][0][30][29].text,root[1][0][30][30].text)
	V_220548 = STIG(root[1][0][31][0][1].text,root[1][0][31][28].text,root[1][0][31][29].text,root[1][0][31][30].text)
	V_220549 = STIG(root[1][0][32][0][1].text,root[1][0][32][28].text,root[1][0][32][29].text,root[1][0][32][30].text)
	V_220550 = STIG(root[1][0][33][0][1].text,root[1][0][33][28].text,root[1][0][33][29].text,root[1][0][33][30].text)
	V_220551 = STIG(root[1][0][34][0][1].text,root[1][0][34][28].text,root[1][0][34][29].text,root[1][0][34][30].text)
	V_220552 = STIG(root[1][0][35][0][1].text,root[1][0][35][28].text,root[1][0][35][29].text,root[1][0][35][30].text)
	V_220553 = STIG(root[1][0][36][0][1].text,root[1][0][36][28].text,root[1][0][36][29].text,root[1][0][36][30].text)
	V_220554 = STIG(root[1][0][37][0][1].text,root[1][0][37][28].text,root[1][0][37][29].text,root[1][0][37][30].text)
	V_220555 = STIG(root[1][0][38][0][1].text,root[1][0][38][28].text,root[1][0][38][29].text,root[1][0][38][30].text)
	V_220556 = STIG(root[1][0][39][0][1].text,root[1][0][39][28].text,root[1][0][39][29].text,root[1][0][39][30].text)
	V_220557 = STIG(root[1][0][40][0][1].text,root[1][0][40][28].text,root[1][0][40][29].text,root[1][0][40][30].text)
	V_220558 = STIG(root[1][0][41][0][1].text,root[1][0][41][28].text,root[1][0][41][29].text,root[1][0][41][30].text)
	V_220559 = STIG(root[1][0][42][0][1].text,root[1][0][42][28].text,root[1][0][42][29].text,root[1][0][42][30].text)
	V_220560 = STIG(root[1][0][43][0][1].text,root[1][0][43][28].text,root[1][0][43][29].text,root[1][0][43][30].text)
	V_220561 = STIG(root[1][0][44][0][1].text,root[1][0][44][28].text,root[1][0][44][29].text,root[1][0][44][30].text)
	V_220563 = STIG(root[1][0][45][0][1].text,root[1][0][45][28].text,root[1][0][45][29].text,root[1][0][45][30].text)
	V_220564 = STIG(root[1][0][46][0][1].text,root[1][0][46][28].text,root[1][0][46][29].text,root[1][0][46][30].text)
	V_220565 = STIG(root[1][0][47][0][1].text,root[1][0][47][28].text,root[1][0][47][29].text,root[1][0][47][30].text)
	V_220566 = STIG(root[1][0][48][0][1].text,root[1][0][48][28].text,root[1][0][48][29].text,root[1][0][48][30].text)
	V_220567 = STIG(root[1][0][49][0][1].text,root[1][0][49][28].text,root[1][0][49][29].text,root[1][0][49][30].text)
	V_220568 = STIG(root[1][0][50][0][1].text,root[1][0][50][28].text,root[1][0][50][29].text,root[1][0][50][30].text)
	V_220569 = STIG(root[1][0][51][0][1].text,root[1][0][51][28].text,root[1][0][51][29].text,root[1][0][51][30].text)

elif ckl_is_from_stigman:
	V_220518 = STIG(root[1][0][1][0][1].text,root[1][0][1][21].text,root[1][0][1][22].text,root[1][0][1][23].text)
	V_220519 = STIG(root[1][0][2][0][1].text,root[1][0][2][21].text,root[1][0][2][22].text,root[1][0][2][23].text)
	V_220520 = STIG(root[1][0][3][0][1].text,root[1][0][3][21].text,root[1][0][3][22].text,root[1][0][3][23].text)
	V_220521 = STIG(root[1][0][4][0][1].text,root[1][0][4][21].text,root[1][0][4][22].text,root[1][0][4][23].text)
	V_220522 = STIG(root[1][0][5][0][1].text,root[1][0][5][21].text,root[1][0][5][22].text,root[1][0][5][23].text)
	V_220523 = STIG(root[1][0][6][0][1].text,root[1][0][6][21].text,root[1][0][6][22].text,root[1][0][6][23].text)
	V_220524 = STIG(root[1][0][7][0][1].text,root[1][0][7][21].text,root[1][0][7][22].text,root[1][0][7][23].text)
	V_220525 = STIG(root[1][0][8][0][1].text,root[1][0][8][21].text,root[1][0][8][22].text,root[1][0][8][23].text)
	V_220526 = STIG(root[1][0][9][0][1].text,root[1][0][9][21].text,root[1][0][9][22].text,root[1][0][9][23].text)
	V_220527 = STIG(root[1][0][10][0][1].text,root[1][0][10][21].text,root[1][0][10][22].text,root[1][0][10][23].text)
	V_220528 = STIG(root[1][0][11][0][1].text,root[1][0][11][21].text,root[1][0][11][22].text,root[1][0][11][23].text)
	V_220529 = STIG(root[1][0][12][0][1].text,root[1][0][12][21].text,root[1][0][12][22].text,root[1][0][12][23].text)
	V_220530 = STIG(root[1][0][13][0][1].text,root[1][0][13][21].text,root[1][0][13][22].text,root[1][0][13][23].text)
	V_220531 = STIG(root[1][0][14][0][1].text,root[1][0][14][21].text,root[1][0][14][22].text,root[1][0][14][23].text)
	V_220532 = STIG(root[1][0][15][0][1].text,root[1][0][15][21].text,root[1][0][15][22].text,root[1][0][15][23].text)
	V_220533 = STIG(root[1][0][16][0][1].text,root[1][0][16][21].text,root[1][0][16][22].text,root[1][0][16][23].text)
	V_220534 = STIG(root[1][0][17][0][1].text,root[1][0][17][21].text,root[1][0][17][22].text,root[1][0][17][23].text)
	V_220535 = STIG(root[1][0][18][0][1].text,root[1][0][18][22].text,root[1][0][18][23].text,root[1][0][18][24].text)
	V_220536 = STIG(root[1][0][19][0][1].text,root[1][0][19][21].text,root[1][0][19][22].text,root[1][0][19][23].text)
	V_220537 = STIG(root[1][0][20][0][1].text,root[1][0][20][21].text,root[1][0][20][22].text,root[1][0][20][23].text)
	V_220538 = STIG(root[1][0][21][0][1].text,root[1][0][21][21].text,root[1][0][21][22].text,root[1][0][21][23].text)
	V_220539 = STIG(root[1][0][22][0][1].text,root[1][0][22][21].text,root[1][0][22][22].text,root[1][0][22][23].text)
	V_220540 = STIG(root[1][0][23][0][1].text,root[1][0][23][21].text,root[1][0][23][22].text,root[1][0][23][23].text)
	V_220541 = STIG(root[1][0][24][0][1].text,root[1][0][24][21].text,root[1][0][24][22].text,root[1][0][24][23].text)
	V_220542 = STIG(root[1][0][25][0][1].text,root[1][0][25][21].text,root[1][0][25][22].text,root[1][0][25][23].text)
	V_220543 = STIG(root[1][0][26][0][1].text,root[1][0][26][21].text,root[1][0][26][22].text,root[1][0][26][23].text)
	V_220544 = STIG(root[1][0][27][0][1].text,root[1][0][27][21].text,root[1][0][27][22].text,root[1][0][27][23].text)
	V_220545 = STIG(root[1][0][28][0][1].text,root[1][0][28][21].text,root[1][0][28][22].text,root[1][0][28][23].text)
	V_220546 = STIG(root[1][0][29][0][1].text,root[1][0][29][21].text,root[1][0][29][22].text,root[1][0][29][23].text)
	V_220547 = STIG(root[1][0][30][0][1].text,root[1][0][30][21].text,root[1][0][30][22].text,root[1][0][30][23].text)
	V_220548 = STIG(root[1][0][31][0][1].text,root[1][0][31][21].text,root[1][0][31][22].text,root[1][0][31][23].text)
	V_220549 = STIG(root[1][0][32][0][1].text,root[1][0][32][22].text,root[1][0][32][23].text,root[1][0][32][24].text)
	V_220550 = STIG(root[1][0][33][0][1].text,root[1][0][33][21].text,root[1][0][33][22].text,root[1][0][33][23].text)
	V_220551 = STIG(root[1][0][34][0][1].text,root[1][0][34][21].text,root[1][0][34][22].text,root[1][0][34][23].text)
	V_220552 = STIG(root[1][0][35][0][1].text,root[1][0][35][21].text,root[1][0][35][22].text,root[1][0][35][23].text)
	V_220553 = STIG(root[1][0][36][0][1].text,root[1][0][36][21].text,root[1][0][36][22].text,root[1][0][36][23].text)
	V_220554 = STIG(root[1][0][37][0][1].text,root[1][0][37][21].text,root[1][0][37][22].text,root[1][0][37][23].text)
	V_220555 = STIG(root[1][0][38][0][1].text,root[1][0][38][21].text,root[1][0][38][22].text,root[1][0][38][23].text)
	V_220556 = STIG(root[1][0][39][0][1].text,root[1][0][39][21].text,root[1][0][39][22].text,root[1][0][39][23].text)
	V_220557 = STIG(root[1][0][40][0][1].text,root[1][0][40][21].text,root[1][0][40][22].text,root[1][0][40][23].text)
	V_220558 = STIG(root[1][0][41][0][1].text,root[1][0][41][21].text,root[1][0][41][22].text,root[1][0][41][23].text)
	V_220559 = STIG(root[1][0][42][0][1].text,root[1][0][42][21].text,root[1][0][42][22].text,root[1][0][42][23].text)
	V_220560 = STIG(root[1][0][43][0][1].text,root[1][0][43][21].text,root[1][0][43][22].text,root[1][0][43][23].text)
	V_220561 = STIG(root[1][0][44][0][1].text,root[1][0][44][21].text,root[1][0][44][22].text,root[1][0][44][23].text)
	V_220563 = STIG(root[1][0][45][0][1].text,root[1][0][45][21].text,root[1][0][45][22].text,root[1][0][45][23].text)
	V_220564 = STIG(root[1][0][46][0][1].text,root[1][0][46][21].text,root[1][0][46][22].text,root[1][0][46][23].text)
	V_220565 = STIG(root[1][0][47][0][1].text,root[1][0][47][22].text,root[1][0][47][23].text,root[1][0][47][24].text)
	V_220566 = STIG(root[1][0][48][0][1].text,root[1][0][48][22].text,root[1][0][48][23].text,root[1][0][48][24].text)
	V_220567 = STIG(root[1][0][49][0][1].text,root[1][0][49][22].text,root[1][0][49][23].text,root[1][0][49][24].text)
	V_220568 = STIG(root[1][0][50][0][1].text,root[1][0][50][21].text,root[1][0][50][22].text,root[1][0][50][23].text)
	V_220569 = STIG(root[1][0][51][0][1].text,root[1][0][51][21].text,root[1][0][51][22].text,root[1][0][51][23].text)
###------------------------------------------------------------------------------------------------------------###

def determine_compliance(current_config="Config not found",expected_config="expected config"): #This function will compare the current config with what is expected and assign the appropriate status.
	if current_stig.status == "Not_Applicable": ### if the STIG status in the CKL file is already marked as Not Applicable, it'll be skipped to avoid false positives. ###
		pass
	
	elif expected_config in current_config: ### if the required config IS found in the current config refined by the lines that were indexed, it'll be declared not a finding. ###
		current_stig.status = "NotAFinding"

	elif expected_config not in current_config: ### if the required config is NOT found in the current config refined by the lines that were indexed, it'll be declared open. ###
		current_stig.status = "Open"


	new_finding_details = (current_stig.status + "\n\nScope of current configuration that was searched:\n\n" + current_config + "\n\n----------\nConfig searched for:\n\n" + expected_config + "\n----------\n")
	current_stig.finding_details = new_finding_details
	print("Current stig status is: " + current_stig.status)
	print("Finding details: " + new_finding_details)
	print("determine_compliance function complete for \n" + current_stig.vuln_id + "\n")


### STIG checks begin. First, the instance attributes will be printed mostly for debugging purposes ###
######### repeat this block of code for all STIG checks #########
print("Beginning STIG check for " + V_220518.vuln_id,V_220518.status,V_220518.comments,V_220518.finding_details + "\n----------\n")
current_stig = V_220518 ### assigns current_stig variable to the corresponding STIG ID ###
print(current_stig)

with open(show_run_config) as f: ### this is opening the config file to search for the STIG-required lines of config ###

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "line vty 5 15" in line: ### this is the string that will be searched for in the config file. Basically a 'header' for the config that will lie underneath of it ###
			current_config = "".join(lines[index:max(0,index+5)]) ### this index+6 number can be changed to any number in order refine the scope of lines that will be searched. ###
			print(current_config)

expected_config = "transport input none" ### this string is the actual config that will be searched for. The pass/fail of the STIG will depend on the presence of this string in the above lines that are indexed ###
print("Triggering determine_compliance function now...")
determine_compliance(current_config,expected_config) ### this calls the function to compare the expected and current configs. The appropriate status (Open, NotAFinding, or Not_Applicable) will be chosen based on the results of that comparison. ###

if ckl_is_from_stigviewer:
	root[1][0][1][28].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][1][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][1][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][1][22].text = current_stig.finding_details

#with open (xmlfile, "wb") as fh: ### this is actually writing the new data to the CKL file. ###
#	tree.write(fh)
######### repeat this block of code for all STIG checks #########



#########-------------------- start of new STIG check --------------------#########
current_config = ""

print(V_220519.vuln_id,V_220519.status,V_220519.comments,V_220519.finding_details)
current_stig = V_220519

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "log config" in line:
			current_config = "".join(lines[index:max(0,index+5)])
			print(current_config)

expected_config = "logging enable"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][2][28].text = current_stig.status
	root[1][0][2][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][2][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][2][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220520.vuln_id,V_220520.status,V_220520.comments,V_220520.finding_details)
current_stig = V_220520

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "log config" in line:
			current_config = "".join(lines[index:max(0,index+5)])
			print(current_config)

expected_config = "logging enable"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][3][28].text = current_stig.status
	root[1][0][3][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][3][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][3][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220521.vuln_id,V_220521.status,V_220521.comments,V_220521.finding_details)
current_stig = V_220521

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "log config" in line:
			current_config = "".join(lines[index:max(0,index+5)])
			print(current_config)

expected_config = "logging enable"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][4][28].text = current_stig.status
	root[1][0][4][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][4][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][4][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220522.vuln_id,V_220522.status,V_220522.comments,V_220522.finding_details)
current_stig = V_220522

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "log config" in line:
			current_config = "".join(lines[index:max(0,index+5)])
			print(current_config)

expected_config = "logging enable"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][5][28].text = current_stig.status
	root[1][0][5][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][5][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][5][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220523.vuln_id,V_220523.status,V_220523.comments,V_220523.finding_details)
current_stig = V_220523

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "line vty 0 4" in line:
			current_config = "".join(lines[index:max(0,index+8)])
			print(current_config)

expected_config = "access-class SSH_LISTv2 in"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][6][28].text = current_stig.status
	root[1][0][6][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][6][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][6][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220524.vuln_id,V_220524.status,V_220524.comments,V_220524.finding_details)
current_stig = V_220524

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "login block-for 900 attempts 3 within 120" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)

expected_config = "login block-for 900 attempts 3 within 120"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][7][28].text = current_stig.status
	root[1][0][7][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][7][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][7][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220525.vuln_id,V_220525.status,V_220525.comments,V_220525.finding_details)
current_stig = V_220525

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "banner login" in line:
			current_config = "".join(lines[index:max(0,index+50)])
			print(current_config)

expected_config = """*********************************************************************
***------------------------ATTENTION!!!---------------------------***
*********************************************************************
***  You are accessing a U.S. Government (USG) Information System ***
***  (IS) that is provided for the USG-authorized use only.       ***
***  By using this IS (which includes any device attached to this ***
***  IS),  you consent to the following conditions:               ***
*** ==============================================================***
*** -The USG routinely intercepts and monitors communications on  ***
***  this IS for purposes including, but not limited to,          ***
***  penetration testing, COMSEC monitoring, network operations   ***
***  and defense, personnel misconduct (PM), law enforcement (LE),***
***  and counterintelligence (CI) investigations.                 ***
***                                                               ***
*** -At any time, the USG may inspect and seize data stored on    ***
***  this IS.                                                     ***
***                                                               ***
*** -Communications using, or data stored on, this IS are not     ***
***  private, are subject to routine monitoring, interception,    ***
***  and search, and may be disclosed or used for any USG-        ***
***  authorized prupose.                                          ***
*** -This IS includes security measures (e.g., authentication     ***
***  and access controls) to protect USG interests--not for your  ***
***  personal benefit or privacy.                                 ***
*** -Notwithstanding the above, using this IS does not            ***
***  constitute consent to PM, LE, or CI investigative searching  ***
***  or monitoring of the content of privileged communications,   ***
***  or work product, related to personal representation or       ***
***  services by attorneys, psychotherapists, or clergy, and      ***
***  their assistants. Such communications and work product are   ***
***  private and confidential.See User Agreement for Details.     ***
***                                                               ***
*********************************************************************
***------------------------ATTENTION!!!---------------------------***
*********************************************************************
"""

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][8][28].text = current_stig.status
	root[1][0][8][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][8][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][8][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220526.vuln_id,V_220526.status,V_220526.comments,V_220526.finding_details)
current_stig = V_220526

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "log config" in line:
			current_config = "".join(lines[index:max(0,index+5)])
			print(current_config)

expected_config = "logging enable"
print("Triggering determine_compliance function now...")
	
determine_compliance(current_config,expected_config) 

if current_stig.status == "NotAFinding":


	with open(show_run_config) as f:
	
		lines = f.readlines()
		for index, line in enumerate(lines):
	
			if "logging userinfo" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
	
	expected_config = "logging userinfo"
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config) 
	
if ckl_is_from_stigviewer:
	root[1][0][9][28].text = current_stig.status
	root[1][0][9][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][9][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][9][22].text = current_stig.finding_details
	
#	with open (xmlfile, "wb") as fh:
#		tree.write(fh)

#elif root[1][0][3][28].text == "Open": ### this part will check for logging enable so that this stig check will only have to check for 'logging userinfo'. This is just for brevity in code here.
#	current_stig.status = "Open"
#	root[1][0][9][28].text = current_stig.status

#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220527.vuln_id,V_220527.status,V_220527.comments,V_220527.finding_details)
current_stig = V_220527

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "login on-failure log" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)

expected_config = "login on-failure log"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)
print("Debug status: " + current_stig.status)
if current_stig.status == "NotAFinding": ### this if statement will only check for the second required config if the first part passes. If it didn't pass, this second check will be skipped since both need to be satisfied in order for this stig to be satisfied.
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):
		
			if "login on-success log" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
	
	expected_config = "login on-success log"
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config)
	current_stig.finding_details = current_stig.finding_details + "\nBoth 'login on-failure log' and 'login on-success log' were found in the configuration."

elif current_stig.status == "Open":
	print("STIG check failed looking for login on-failure log so it did not look for login on-success log.")
	if ckl_is_from_stigviewer:
		root[1][0][10][30].text = "STIG check failed looking for login on-failure log so it did not look for login on-success log."
	elif ckl_is_from_stigman:
		root[1][0][10][23].text = "STIG check failed looking for login on-failure log so it did not look for login on-success log."
		


if ckl_is_from_stigviewer:
	root[1][0][10][28].text = current_stig.status
	root[1][0][10][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][10][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][10][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)

#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220528.vuln_id,V_220528.status,V_220528.comments,V_220528.finding_details)
current_stig = V_220528

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "service timestamps log datetime msec localtime show-timezone" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			expected_config = current_config
			print(current_config)

		elif "service timestamps log" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)
			expected_config = "service timestamps log datetime localtime"



print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][11][28].text = current_stig.status
	root[1][0][11][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][11][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][11][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220529.vuln_id,V_220529.status,V_220529.comments,V_220529.finding_details)
current_stig = V_220529

#expected_config = "log-input"

deny_acls = []



with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):
		if "deny" in line:
			deny_acls.append(line)

for each_acl in deny_acls:
#	if each_acl[-1] == "log-input":
	if "log-input" in each_acl:
		print("each ACL has log-input configured")
		y = "pass"
		pass
	elif "log-input" not in each_acl:
		current_config = "".join(lines[index:max(0,index+1)])
		print("An ACL was found to not have log-input configured: \n" + each_acl)
		print("\n".join(map(str,deny_acls)))
		print(current_config)
		y = "fail"
		break

print("Comparing 'y' varaible to determine pass/fail...")

if y == "fail":
	if ckl_is_from_stigviewer:
		root[1][0][12][28].text = "Open"
		root[1][0][12][29].text = "An ACL was found to not have log-input configured: \n" + "\n".join(map(str,deny_acls))
	elif ckl_is_from_stigman:
		root[1][0][12][21].text = "Open"
		root[1][0][12][22].text = "An ACL was found to not have log-input configured: \n" + "\n".join(map(str,deny_acls))

elif y == "pass":
	if ckl_is_from_stigviewer:
		root[1][0][12][28].text = "NotAFinding"
		root[1][0][12][29].text = "All deny lines were found to have 'log-input' configured: \n" + "\n".join(map(str,deny_acls))
	elif ckl_is_from_stigman:
		root[1][0][12][21].text = "NotAFinding"
		root[1][0][12][22].text = "All deny lines were found to have 'log-input' configured: \n" + "\n".join(map(str,deny_acls))

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220530.vuln_id,V_220530.status,V_220530.comments,V_220530.finding_details)
current_stig = V_220530

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "log config" in line:
			current_config = "".join(lines[index:max(0,index+5)])
			print(current_config)

expected_config = "logging enable"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][13][28].text = current_stig.status
	root[1][0][13][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][13][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][13][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220531.vuln_id,V_220531.status,V_220531.comments,V_220531.finding_details)
current_stig = V_220531

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "file privilege 15" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)

expected_config = "file privilege 15"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][14][28].text = current_stig.status
	root[1][0][14][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][14][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][14][22].text = current_stig.finding_details


with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220532.vuln_id,V_220532.status,V_220532.comments,V_220532.finding_details)
current_stig = V_220532

with open(show_run_config) as f: ### this check will purely check for file privelege 15, since if it's N/A it will skip this anyways. If it's not N/A, that means this should be configured.

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "file privilege 15" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)

expected_config = "file privilege 15"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][15][28].text = current_stig.status
	root[1][0][15][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][15][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][15][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220533.vuln_id,V_220533.status,V_220533.comments,V_220533.finding_details)
current_stig = V_220533

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "file privilege 15" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)

expected_config = "file privilege 15"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][16][28].text = current_stig.status
	root[1][0][16][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][16][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][16][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220534.vuln_id,V_220534.status,V_220534.comments,V_220534.finding_details)
current_stig = V_220534

unnecessary_services = ["boot network","ip boot server","ip bootp server","ip dns server","ip identd","ip finger","ip http server","ip rcmd rcp-enable","ip rcmd rsh-enable","service config","service finger","service tcp-small-servers","service udp-small-servers"]

with open(show_run_config) as f:

	for line in f:
		for each_service in unnecessary_services:
			if each_service in line:
				if "no" not in line:
					current_stig.status = "Open"
					current_stig.finding_details = "One or more unnecessary services have been found in the configuration: \n" + each_service
					print("Unnecessary service found, this STIG has failed.")
					print(current_stig.finding_details)
				else:
					current_stig.status = "NotAFinding"
					current_stig.finding_details = "None of the listed unnecessary services were found in the configuration."
					print("No unnecessary services found. Nice!")

#print("Triggering determine_compliance function now...")
#determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][17][28].text = current_stig.status
	root[1][0][17][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][17][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][17][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



######-------------------- start of new STIG check --------------------#########
## why is this one breaking the XML schema??? Fix later.###
current_config = ""
print(V_220535.vuln_id,V_220535.status,V_220535.comments,V_220535.finding_details)
current_stig = V_220535

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		username_config = ["username","privilege"]

		if all(x in line for x in username_config):
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)
		expected_config = "privilege 15"

print("Triggering determine_compliance function now...")
determine_compliance(current_config,expected_config) 

if current_stig.status == "NotAFinding":
	current_config = ""
	aaa_auth_list = []
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):

			if "aaa authentication login default" in line:
				print(line[-6:])
				if line[-6:] == """local
""":
					print(line)
					current_config = "".join(lines[index:max(0,index+1)])
					print(current_config)
					expected_config = current_config
				else:
					current_config = "".join(lines[index:max(0,index+1)])
					expected_config = "Local login is NOT enabled only if authentication server is unreachabkle."
#				aaa_auth_list = line
#				print(aaa_auth_list)
#				print(aaa_auth_list[-1])
#				if aaa_auth_list[-1] != "local":
#					current_config = aaa_auth_list[-1]
#					expected_config = "local"
					
print("Triggering determine_compliance function now...")
determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][18][28].text = current_stig.status
	root[1][0][18][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][18][22].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][18][23].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#######-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220536.vuln_id,V_220536.status,V_220536.comments,V_220536.finding_details)
current_stig = V_220536

x = 0

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "ip ssh version 2" in line:

			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)
			expected_config = "ip ssh version 2"
			print("Triggering determine_compliance function now...")
			determine_compliance(current_config,expected_config)
			if current_stig.status == "NotAFinding":
				x += 1

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "ip ssh server algorithm encryption" in line:

			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)
			expected_config = "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr"
			print("Triggering determine_compliance function now...")
			determine_compliance(current_config,expected_config)
			if current_stig.status == "NotAFinding":
				x += 1
print(x)

if x == 2:
	current_stig.status = "NotAFinding"
	current_stig.finding_details = "Both 'ip ssh version 2' and 'ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr' were found in the configuration."
	if ckl_is_from_stigviewer:
		root[1][0][19][28].text = current_stig.status
		root[1][0][19][29].text = current_stig.finding_details
	elif ckl_is_from_stigman:
		root[1][0][19][21].text = current_stig.status
		root[1][0][19][22].text = current_stig.finding_details
else:
	current_stig.status = "Open"
	current_stig.finding_details = "One of the required configs were not found in the configuration."
	if ckl_is_from_stigviewer:
		root[1][0][19][28].text = current_stig.status
		root[1][0][19][29].text = current_stig.finding_details
	elif ckl_is_from_stigman:
		root[1][0][19][21].text = current_stig.status
		root[1][0][19][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)



#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220537.vuln_id,V_220537.status,V_220537.comments,V_220537.finding_details)
current_stig = V_220537

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "aaa common-criteria policy" in line:
			current_config = "".join(lines[index:max(0,index+10)])
			print(current_config)

expected_config = "min-length 15"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][20][28].text = current_stig.status
	root[1][0][20][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][20][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][20][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220538.vuln_id,V_220538.status,V_220538.comments,V_220538.finding_details)
current_stig = V_220538

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "aaa common-criteria policy" in line:
			current_config = "".join(lines[index:max(0,index+10)])
			print(current_config)

expected_config = "upper-case 1"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][21][28].text = current_stig.status
	root[1][0][21][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][21][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][21][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220539.vuln_id,V_220539.status,V_220539.comments,V_220539.finding_details)
current_stig = V_220539

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "aaa common-criteria policy" in line:
			current_config = "".join(lines[index:max(0,index+10)])
			print(current_config)

expected_config = "lower-case 1"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][22][28].text = current_stig.status
	root[1][0][22][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][22][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][22][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220540.vuln_id,V_220540.status,V_220540.comments,V_220540.finding_details)
current_stig = V_220540

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "aaa common-criteria policy" in line:
			current_config = "".join(lines[index:max(0,index+10)])
			print(current_config)

expected_config = "numeric-count 1"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][23][28].text = current_stig.status
	root[1][0][23][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][23][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][23][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220541.vuln_id,V_220541.status,V_220541.comments,V_220541.finding_details)
current_stig = V_220541

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "aaa common-criteria policy" in line:
			current_config = "".join(lines[index:max(0,index+10)])
			print(current_config)

expected_config = "special-case 1"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][24][28].text = current_stig.status
	root[1][0][24][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][24][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][24][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220542.vuln_id,V_220542.status,V_220542.comments,V_220542.finding_details)
current_stig = V_220542

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "aaa common-criteria policy" in line:
			current_config = "".join(lines[index:max(0,index+10)])
			print(current_config)

expected_config = "char-changes 8"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][25][28].text = current_stig.status
	root[1][0][25][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][25][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][25][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220543.vuln_id,V_220543.status,V_220543.comments,V_220543.finding_details)
current_stig = V_220543
z = 0

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "service password-encryption" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)

expected_config = "service password-encryption"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

print("Debug status: " + current_stig.status)

if current_stig.status == "NotAFinding": ### this if statement will only check for the second required config if the first part passes. If it didn't pass, this second check will be skipped since both need to be satisfied in order for this stig to be satisfied.
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):
		
			if "enable secret" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
	
	expected_config = "enable secret "
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config)

#if current_stig.status == "Open": ### this if statement will only check for the second required config if the first part passes. If it didn't pass, this second check will be skipped since both need to be satisfied in order for this stig to be satisfied.
#	with open(show_run_config) as f:
#		lines = f.readlines()
#		for index, line in enumerate(lines):
#		
#			if "enable secret" in line:
#				current_config = "".join(lines[index:max(0,index+1)])
#				print(current_config)
#	
#	expected_config = "enable secret 9"
#	
#	print("Triggering determine_compliance function now...")
#	
#	determine_compliance(current_config,expected_config)

if current_stig.status == "NotAFinding":
	current_stig.finding_details = "Both 'service password-encryption' and 'enable secret' found in config."

elif current_stig.status == "Open":
	print("Either 'service password-encryption' or 'enable secret' was NOT found in config.")
	if ckl_is_from_stigviewer:
		root[1][0][26][30].text = "Either 'service password-encryption' or 'enable secret' was NOT found in config."
	elif ckl_is_from_stigman:
		root[1][0][26][23].text = "Either 'service password-encryption' or 'enable secret' was NOT found in config."

if ckl_is_from_stigviewer:
	root[1][0][26][28].text = current_stig.status
	root[1][0][26][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][26][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][26][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########
current_config = ""
print(V_220544.vuln_id,V_220544.status,V_220544.comments,V_220544.finding_details)
current_stig = V_220544
z = 0

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "line vty 0" in line:
			current_config = "".join(lines[index:max(0,index+10)])
			print(current_config)

expected_config = "exec-timeout 10 0"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

print("Debug status: " + current_stig.status)

if current_stig.status == "NotAFinding": ### this if statement will only check for the second required config if the first part passes. If it didn't pass, this second check will be skipped since both need to be satisfied in order for this stig to be satisfied.
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):
		
			if "line con 0" in line:
				current_config = "".join(lines[index:max(0,index+10)])
				print(current_config)
	
	expected_config = "exec-timeout 10 0"
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config)

if current_stig.status == "NotAFinding": ### this if statement will only check for the second required config if the first part passes. If it didn't pass, this second check will be skipped since both need to be satisfied in order for this stig to be satisfied.
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):
		
			if "no ip http server" in line:
				current_stig.status = "NotAFinding"
				break
			elif "no ip http server" not in line:
				if "ip http timeout-policy idle" in line:
					current_config = "".join(lines[index:max(0,index+1)])
					print(current_config)
					expected_config = "ip http timeout-policy idle 600"
					determine_compliance(current_config,expected_config)


if current_stig.status == "NotAFinding":
	current_stig.finding_details = "Timeout values on vty, http (if applicable) and console lines are set to 10 minutes."
	if ckl_is_from_stigviewer:
		root[1][0][27][30].text = ""
	elif ckl_is_from_stigman:
		root[1][0][27][23].text = ""

elif current_stig.status == "Open":
	if ckl_is_from_stigviewer:
		root[1][0][27][30].text = "A timeout value was not set to 10 minutes on either the vty, console, or http server."
	elif ckl_is_from_stigman:
		root[1][0][27][23].text = "A timeout value was not set to 10 minutes on either the vty, console, or http server."

if ckl_is_from_stigviewer:
	root[1][0][27][28].text = current_stig.status
	root[1][0][27][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][27][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][27][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""

print(V_220545.vuln_id,V_220545.status,V_220545.comments,V_220545.finding_details)
current_stig = V_220545

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "log config" in line:
			current_config = "".join(lines[index:max(0,index+5)])
			print(current_config)

expected_config = "logging enable"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][28][28].text = current_stig.status
	root[1][0][28][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][28][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][28][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220546.vuln_id,V_220546.status,V_220546.comments,V_220546.finding_details)
current_stig = V_220526

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "log config" in line:
			current_config = "".join(lines[index:max(0,index+10)])
			print(current_config)

expected_config = "logging enable"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

print("Debug status: " + current_stig.status)

if current_stig.status == "NotAFinding": ### this if statement will only check for the second required config if the first part passes. If it didn't pass, this second check will be skipped since both need to be satisfied in order for this stig to be satisfied.
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):
		
			if "logging userinfo" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
	
	expected_config = "logging userinfo"
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config)

if current_stig.status == "NotAFinding":
	current_stig.finding_details = "'logging userinfo' and 'logging enable' were found in the config."
	if ckl_is_from_stigviewer:
		root[1][0][29][30].text = ""
	elif ckl_is_from_stigman:
		root[1][0][29][23].text = ""

if ckl_is_from_stigviewer:
	root[1][0][29][28].text = current_stig.status
	root[1][0][29][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][29][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][29][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""

print(V_220547.vuln_id,V_220547.status,V_220547.comments,V_220547.finding_details)
current_stig = V_220547

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "logging buffered" in line:
			current_config = "".join(lines[index:max(0,index+5)])
			print(current_config)

expected_config = "informational"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][30][28].text = current_stig.status
	root[1][0][30][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][30][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][30][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220548.vuln_id,V_220548.status,V_220548.comments,V_220548.finding_details)
current_stig = V_220548

with open(show_logging_config) as f:
	lines = f.readlines()
	for index, line in enumerate(lines):
			
		if offline_mode == True:
			expected_config = "".join(lines)	
			current_config = ""
		else:
	
#		if "Trap logging: level informational" in line:
#			current_config = "".join(lines[index:max(0,index+1)])
#			print(current_config)
			if "Trap logging:" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
				if "alert" or "emergency" not in line:
					expected_config = current_config
					break
				else:
					expected_config = "Trap logging must be set critical or lower!"

print("Triggering determine_compliance function now...")
determine_compliance(current_config,expected_config)

if current_stig.status == "NotAFinding":
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):

			if "logging host " in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
				expected_config = current_config
				print("Triggering secondary determine_compliance function now...")
				determine_compliance(current_config,expected_config)

#if current_stig.status == "NotAFinding":
#	current_stig.finding_details = "A logging host and 'logging trap critical was found in the configuration."

if ckl_is_from_stigviewer:
	root[1][0][31][28].text = current_stig.status
	root[1][0][31][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][31][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][31][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#######-------------------- start of new STIG check --------------------#########
## this check breaks the XML schema... fix later! ###
current_config = ""
print(V_220549.vuln_id,V_220549.status,V_220549.comments,V_220549.finding_details)
current_stig = V_220549

#expected_config = "log-input"

ntp_servers = []

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):
		if "ntp server" in line:
			ntp_servers.append(line)

if len(ntp_servers) < 2:
	if ckl_is_from_stigviewer:
		root[1][0][32][28].text = "Open"
		root[1][0][32][29].text = "Device does not have multiple NTP servers configured: \n" + "".join(map(str,ntp_servers))
	elif ckl_is_from_stigman:
		root[1][0][32][22].text = "Open"
		root[1][0][32][23].text = "Device does not have multiple NTP servers configured: \n" + "".join(map(str,ntp_servers))
elif len(ntp_servers) >= 2:
	if ckl_is_from_stigviewer:
		root[1][0][32][28].text = "NotAFinding"
		root[1][0][32][29].text = "Device has multiple NTP servers configured: \n" + "".join(map(str,ntp_servers))
	elif ckl_is_from_stigman:
		root[1][0][32][22].text = "NotAFinding"
		root[1][0][32][23].text = "Device has multiple NTP servers configured: \n" + "".join(map(str,ntp_servers))

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220550.vuln_id,V_220550.status,V_220550.comments,V_220550.finding_details)
current_stig = V_220550

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "service timestamps log datetime msec localtime show-timezone" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				expected_config = current_config
				print(current_config)

		elif "service timestamps log" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)

expected_config = "service timestamps log datetime localtime"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][33][28].text = current_stig.status
	root[1][0][33][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][33][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][33][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220551.vuln_id,V_220551.status,V_220551.comments,V_220551.finding_details)
current_stig = V_220551 ### this stig will have improved accuracy if paramiko is used to gather config outputs ###

with open(show_version_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):
			
		if offline_mode == True:
			expected_config = "".join(lines)	
			current_config = ""
		else:
			
			expected_config = "UTC"
			if "Time source is NTP" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)



print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

print("Debug status: " + current_stig.status)

if current_stig.status == "NotAFinding": ### this if statement will only check for the second required config if the first part passes. If it didn't pass, this second check will be skipped since both need to be satisfied in order for this stig to be satisfied.
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):


			if "service timestamps log datetime msec localtime show-timezone" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				expected_config = current_config
				print(current_config)
		
			elif "service timestamps log" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
	
	expected_config = "service timestamps log datetime localtime"
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config)

if ckl_is_from_stigviewer:
	root[1][0][34][28].text = current_stig.status
	root[1][0][34][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][34][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][34][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220552.vuln_id,V_220552.status,V_220552.comments,V_220552.finding_details)
current_stig = V_220552 ### this check will have improved accuracy if paramiko is used to gather configs ###

with open(snmp_user_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if offline_mode == True:
			expected_config = "".join(lines)	
			current_config = ""
		else:

			expected_config = "SHA"
			if "Authentication Protocol:" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)



print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][35][28].text = current_stig.status
	root[1][0][35][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][35][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][35][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220553.vuln_id,V_220553.status,V_220553.comments,V_220553.finding_details)
current_stig = V_220553 ### this check will have improved accuracy if paramiko is used to gather configs ###

with open(snmp_user_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):
			
		if offline_mode == True:
			expected_config = "".join(lines)	
			current_config = ""
		else:

			expected_config = "AES256"
			if "Privacy Protocol" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)



print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][36][28].text = current_stig.status
	root[1][0][36][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][36][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][36][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220554.vuln_id,V_220554.status,V_220554.comments,V_220554.finding_details)
current_stig = V_220554 ### this check will have improved accuracy if paramiko is used to gather configs ###

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "ntp authentication-key" in line:
			current_config = "".join(lines[index:max(0,index+15)])
			print(current_config)

expected_config = "ntp authenticate"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

if current_stig.status == "NotAFinding":
	current_config = ""
	with open(show_run_config) as f:

		lines = f.readlines()
		for index, line in enumerate(lines):
	
			if "ntp authentication-key 1" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)

	expected_config = "ntp authentication-key 1 md5"
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config)


if current_stig.status == "NotAFinding":
	current_config = ""
	with open(show_run_config) as f:

		lines = f.readlines()
		for index, line in enumerate(lines):
	
			if "ntp authentication-key" in line:
				current_config = "".join(lines[index:max(0,index+10)])
				print(current_config)

	expected_config = "ntp trusted-key 1"
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config)


if current_stig.status == "NotAFinding":
	current_config = ""
	with open(show_run_config) as f:

		lines = f.readlines()
		for index, line in enumerate(lines):
	
			if "ntp server" in line:
					current_config = "".join(lines[index:max(0,index+1)])
			#print(current_config)

	expected_config = "key 1"
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config)


if ckl_is_from_stigviewer:
	root[1][0][37][28].text = current_stig.status
	root[1][0][37][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][37][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][37][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)

#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220555.vuln_id,V_220555.status,V_220555.comments,V_220555.finding_details)
current_stig = V_220555


with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "ip ssh version 2" in line:

			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)
			expected_config = "ip ssh version 2"

print("Triggering determine_compliance function now...")
determine_compliance(current_config,expected_config)


if current_stig.status == "NotAFinding":

	with open(show_run_config) as f:
	
		lines = f.readlines()
		for index, line in enumerate(lines):
	
			if "ip ssh server algorithm mac" in line:
	
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
	
				expected_config = "hmac-sha2-512 hmac-sha2-256"
	
				print("Triggering determine_compliance function now...")
				determine_compliance(current_config,expected_config)

if ckl_is_from_stigviewer:
	root[1][0][38][28].text = current_stig.status
	root[1][0][38][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][38][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][38][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220556.vuln_id,V_220556.status,V_220556.comments,V_220556.finding_details)
current_stig = V_220556

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "ip ssh server algorithm encryption" in line:

			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)
			expected_config = "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr"
			print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

if ckl_is_from_stigviewer:
	root[1][0][39][28].text = current_stig.status
	root[1][0][39][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][39][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][39][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220557.vuln_id,V_220557.status,V_220557.comments,V_220557.finding_details)
current_stig = V_220557

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "control-plane" in line:

			current_config = "".join(lines[index:max(0,index+3)])
			print(current_config)

			expected_config = """control-plane
 service-policy input system-cpp-policy
"""

			print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

if ckl_is_from_stigviewer:
	root[1][0][40][28].text = current_stig.status
	root[1][0][40][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][40][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][40][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220558.vuln_id,V_220558.status,V_220558.comments,V_220558.finding_details)
current_stig = V_220558

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "log config" in line:
			current_config = "".join(lines[index:max(0,index+10)])
			print(current_config)

expected_config = "logging enable"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

print("Debug status: " + current_stig.status)

if current_stig.status == "NotAFinding": ### this if statement will only check for the second required config if the first part passes. If it didn't pass, this second check will be skipped since both need to be satisfied in order for this stig to be satisfied.
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):
		
			if "logging userinfo" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
	
	expected_config = "logging userinfo"
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config)

if current_stig.status == "NotAFinding":
	current_stig.finding_details = "'logging userinfo' and 'logging enable' were found in the config."

if ckl_is_from_stigviewer:
	root[1][0][41][28].text = current_stig.status
	root[1][0][41][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][41][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][41][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""

print(V_220559.vuln_id,V_220559.status,V_220559.comments,V_220559.finding_details)
current_stig = V_220559

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "log config" in line:
			current_config = "".join(lines[index:max(0,index+5)])
			print(current_config)

expected_config = "logging enable"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][42][28].text = current_stig.status
	root[1][0][42][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][42][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][42][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220560.vuln_id,V_220560.status,V_220560.comments,V_220560.finding_details)
current_stig = V_220560

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "login on-failure log" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)

expected_config = "login on-failure log"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)
print("Debug status: " + current_stig.status)
if current_stig.status == "NotAFinding": ### this if statement will only check for the second required config if the first part passes. If it didn't pass, this second check will be skipped since both need to be satisfied in order for this stig to be satisfied.
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):
		
			if "login on-success log" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
	
	expected_config = "login on-success log"
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config)
	current_stig.finding_details = current_stig.finding_details + "\nBoth 'login on-failure log' and 'login on-success log' were found in the configuration."

elif current_stig.status == "Open":
	print("STIG check failed looking for login on-failure log so it did not look for login on-success log.")
	if ckl_is_from_stigviewer:
		root[1][0][43][30].text = "STIG check failed looking for login on-failure log so it did not look for login on-success log."
	elif ckl_is_from_stigman:
		root[1][0][43][23].text = "STIG check failed looking for login on-failure log so it did not look for login on-success log."


if ckl_is_from_stigviewer:
	root[1][0][43][28].text = current_stig.status
	root[1][0][43][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][43][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][43][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)

#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""

print(V_220561.vuln_id,V_220561.status,V_220561.comments,V_220561.finding_details)
current_stig = V_220561

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "log config" in line:
			current_config = "".join(lines[index:max(0,index+5)])
			print(current_config)

expected_config = "logging enable"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config) 

if ckl_is_from_stigviewer:
	root[1][0][44][28].text = current_stig.status
	root[1][0][44][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][44][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][44][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220563.vuln_id,V_220563.status,V_220563.comments,V_220563.finding_details)
current_stig = V_220563

with open(show_run_config) as f:
	lines = f.readlines()
	for index, line in enumerate(lines):
	
		if "login on-success log" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)
	
expected_config = "login on-success log"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

if ckl_is_from_stigviewer:
	root[1][0][45][28].text = current_stig.status
	root[1][0][45][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][45][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][45][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)

#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220564.vuln_id,V_220564.status,V_220564.comments,V_220564.finding_details)
current_stig = V_220564

with open(show_run_config) as f:

	lines = f.readlines()
	for index, line in enumerate(lines):

		if "logging host" in line:
			current_config = "".join(lines[index:max(0,index+10)])
			print(current_config)

expected_config = "logging host"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

print("Debug status: " + current_stig.status)

if current_stig.status == "NotAFinding": ### this if statement will only check for the second required config if the first part passes. If it didn't pass, this second check will be skipped since both need to be satisfied in order for this stig to be satisfied.
	current_config = ""
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):
		
			if "logging trap alert" or "logging trap emergency" not in line:
				current_config = "(logging level not set to alert or emergency)"
				#print(current_config)
				expected_config = "(logging level not set to alert or emergency)"
			elif "logging trap alert" or "logging trap emergency" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				#print(current_config)
				expected_config = "(logging level set to alert or emergency. Must be set to critical or lower!)"
	
	print("Triggering determine_compliance function now...")
	
	determine_compliance(current_config,expected_config)

if current_stig.status == "NotAFinding":
	current_stig.finding_details = "A logging host and 'logging trap critical was found in the configuration."

if ckl_is_from_stigviewer:
	root[1][0][46][28].text = current_stig.status
	root[1][0][46][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][46][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][46][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)
#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220565.vuln_id,V_220565.status,V_220565.comments,V_220565.finding_details)
current_stig = V_220565

with open(show_run_config) as f:
	lines = f.readlines()
	for index, line in enumerate(lines):
	
		if "line vty 0 4" in line:
			current_config = "".join(lines[index:max(0,index+5)])
			print(current_config)
	
expected_config = "login authentication"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

if current_stig.status == "NotAFinding":
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):
		
			if "line con 0" in line:
				current_config = "".join(lines[index:max(0,index+5)])
				print(current_config)
		
		expected_config = "login authentication"
		
		print("Triggering determine_compliance function now...")
		
		determine_compliance(current_config,expected_config)


if ckl_is_from_stigviewer:
	root[1][0][47][28].text = current_stig.status
	root[1][0][47][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][47][22].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][47][23].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)

#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220566.vuln_id,V_220566.status,V_220566.comments,V_220566.finding_details)
current_stig = V_220566

backup_app_lines = ['cli command "enable"', 'info type', 'cli command "copy running-config scp:"', 'syslog priority informational msg "Configuration backup was executed"']

with open(show_run_config) as f:
	lines = f.readlines()
	for index, line in enumerate(lines):
	
		if "event manager applet BACKUP_CONFIG" in line:
			current_config = "".join(lines[index:max(0,index+20)])
			for each_backup_config_line in backup_app_lines:
				if each_backup_config_line in current_config:
					expected_config = current_config
				elif each_backup_config_line not in current_config:
					expected_config = "One of the applet configs are missing. Please review the applet configuration to verify!"
					current_config = each_backup_config_line
					break

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

if ckl_is_from_stigviewer:
	root[1][0][48][28].text = current_stig.status
	root[1][0][48][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][48][22].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][48][23].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)

#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220567.vuln_id,V_220567.status,V_220567.comments,V_220567.finding_details)
current_stig = V_220567

with open(show_run_config) as f:
	lines = f.readlines()
	for index, line in enumerate(lines):
	
		if "crypto pki trustpoint" in line:
			current_config = "".join(lines[index:max(0,index+1)])
			print(current_config)

expected_config = "CA"

print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

if ckl_is_from_stigviewer:
	root[1][0][49][28].text = current_stig.status
	root[1][0][49][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][49][22].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][49][23].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)

#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220568.vuln_id,V_220568.status,V_220568.comments,V_220568.finding_details)
current_stig = V_220568

with open(show_logging_config) as f:
	lines = f.readlines()
	
	if offline_mode == True:
		expected_config = "".join(lines)	
		current_config = ""
	else:
	
		for index, line in enumerate(lines):
		
#			if "Trap logging: level informational" in line:
#				current_config = "".join(lines[index:max(0,index+1)])
#				print(current_config)
			if "Trap logging:" in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
				if "alert" or "emergency" not in line:
					expected_config = current_config
					break
				else:
					expected_config = "Trap logging must be set critical or lower!"

print("Triggering determine_compliance function now...")
determine_compliance(current_config,expected_config)

if current_stig.status == "NotAFinding":
	with open(show_run_config) as f:
		lines = f.readlines()
		for index, line in enumerate(lines):

			if "logging host " in line:
				current_config = "".join(lines[index:max(0,index+1)])
				print(current_config)
				expected_config = current_config
				print("Triggering secondary determine_compliance function now...")
				determine_compliance(current_config,expected_config)


if ckl_is_from_stigviewer:
	root[1][0][50][28].text = current_stig.status
	root[1][0][50][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][50][21].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][50][22].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)

#########-------------------- end of this STIG check --------------------#########



#########-------------------- start of new STIG check --------------------#########
current_config = ""
print(V_220569.vuln_id,V_220569.status,V_220569.comments,V_220569.finding_details)
current_stig = V_220569

with open(show_version_config) as f:
	lines = f.readlines()
	for index, line in enumerate(lines):

			
		if offline_mode == True:
			expected_config = "".join(lines)	
			current_config = ""
		else:
			
			expected_config = "16.9.8"
			if "Cisco IOS XE Software" in line:
				current_config = "".join(lines[index:max(0,index+2)])
				print(current_config)



print("Triggering determine_compliance function now...")

determine_compliance(current_config,expected_config)

if ckl_is_from_stigviewer:
	root[1][0][51][28].text = current_stig.status
	root[1][0][51][29].text = current_stig.finding_details
elif ckl_is_from_stigman:
	root[1][0][51][22].text = current_stig.status ### this is assigning the new Status to the dictionary location in the CKL file that will be updated. ###
	root[1][0][51][23].text = current_stig.finding_details

with open (xmlfile, "wb") as fh:
	tree.write(fh)

#########-------------------- end of this STIG check --------------------#########

####################################################### END OF STIG CHECKS! #######################################################

# Cleanup task to remove the config text files that were created
if offline_mode == False:
	os.remove("show_run.txt")
os.remove("show_snmp_user.txt")
os.remove("show_version.txt")
os.remove("show_logging.txt")

print("Cleanup finished.")

# Below code is to re-add the STIG Manager comment that identifies the CKL as from STIGMAN. This is done because when the CKL is modified, the STIGMAN headers are removed.
# By re-adding the STIG Manager comment, if the same CKL is re-ran through this script, it will know to still look at the STIGMAN dictionary locations. Otherwise, it will
# 	think it's from STIG Viewer and look at the wrong locations.

if ckl_is_from_stigman:
	with open(xmlfile, "a") as myxmlfile:
		myxmlfile.write("\n<!-- STIG Manager -->")


print(input("Script complete. Press enter to finish."))