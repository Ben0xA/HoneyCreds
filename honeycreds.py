#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: Ben Ten (Ben0xA)
# HoneyCreds - Detecting LLMNR/NBNS/HTTP Listeners
# Updated: 5/9/2021
# Version: 0.2

# Requires:
# python 3
# smbprotocol
# cffi
# splunk-sdk

import smbclient
import os
import subprocess
import logging
import time
import sys
import requests
import socket
import threading
import splunklib.client as client
from datetime import datetime
from signal import signal, SIGINT

# --------- SETTINGS ----------
# You can set these once or specify them on the command line.
# Please... change these... really. If I see this on a pentest, I will cry.

#Choose a legit looking username
def_username = 'honeycreds' 

#This can match your current Short Domain
def_domain   = 'TSDEV'

#Make this whatever you want. Note: HTTP requests will send this in plaintext
def_password = 'This is a honey cred account.'

#The FQDN. Leave .local at the end.
def_fqdn     = 'ts-dev-mx.local'

#The hostname that DOES NOT EXIST but looks legit.
def_hostname = 'HNECRD01'

#The log file and location
def_logfile  = 'honeycreds.log'

#Ability to turn SMB or HTTP on or off. Set to "OFF" to turn off.
SMB = 'ON'
HTTP = 'ON'

#The time to pause in seconds between requests.
SMB_SLEEP = 5
HTTP_SLEEP = 12

#Forwarders
SPLUNK = 'ON'
ELK = 'OFF' #Coming Soon

#Splunk Forwarding
SPLUNK_HOSTNAME = 'localhost'
SPLUNK_PORT = 8089
SPLUNK_USERNAME = 'admin'
SPLUNK_PASSWORD = None
SPLUNK_TOKEN = None
SPLUNK_INDEX = 'honeycreds'

# --------- STOP ----------
# Do not change anything below this line.
smb_Thread = None
http_Thread = None
smb_exit = threading.Event()
http_exit = threading.Event()
splunk_service = None
splunk_index = None
local_hostname = socket.gethostname()

def signal_handler(sig, frame):	
	global smb_Thread, http_Thread, exit
	print('')
	print('[*] Exiting...')	
	if smb_Thread and smb_Thread.is_alive():
		print('[*] Terminating SMB Client, please wait...')		
		smb_exit.set()
		smb_Thread.join()
		print('[*] SMB Client terminated.')
	if http_Thread and http_Thread.is_alive():
		print('[*] Terminating HTTP Client, please wait...')		
		http_exit.set()
		http_Thread.join()
		print('[*] HTTP Client terminated.')

def init():
	global SMB, HTTP
	log_format = ('[%(asctime)s] %(levelname)-8s %(name)-12s %(message)s')	
	logging.basicConfig(
		level=logging.CRITICAL,
		format=log_format,
		filename=(def_logfile)
	)
	SMB = str.upper(SMB)
	HTTP = str.upper(HTTP)

def init_splunk():
	global splunk_service, splunk_index
	global SPLUNK_HOSTNAME,SPLUNK_PORT, SPLUNK_USERNAME, SPLUNK_PASSWORD, SPLUNK_TOKEN, SPLUNK_INDEX	
	if SPLUNK_TOKEN != None:
		splunk_service = client.connect(host=SPLUNK_HOSTNAME, port=SPLUNK_PORT, splunkToken=SPLUNK_TOKEN)
	else:
		splunk_service = client.connect(host=SPLUNK_HOSTNAME, port=SPLUNK_PORT, username=SPLUNK_USERNAME, password=SPLUNK_PASSWORD)

	#Get or create index
	try:
		splunk_index = splunk_service.indexes[SPLUNK_INDEX]
	except:
		splunk_index = splunk_service.indexes.create(SPLUNK_INDEX)

def banner():
	oncolor = termcolor.GREEN
	print(termcolor.YELLOW + termcolor.BOLD + '       .-=-=-=-.        ' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + '     (`-=-=-=-=-`)      ' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + '   (`-=-=-=-=-=-=-`)    ' + termcolor.WHITE + '  _   _                              ___                     _       ' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + '  (`-=-=-=-=-=-=-=-`)   ' + termcolor.WHITE + ' ( ) ( )                            (  _ \\                  ( )      ' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + ' ( `-=-=-=-(@)-=-=-` )  ' + termcolor.WHITE + ' | |_| |   _     ___     __   _   _ | ( (_) _ __    __     _| |  ___ ' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + ' (`-=-=-=-=-=-=-=-=-`)  ' + termcolor.WHITE + ' |  _  | / _ \\ /  _  \\ / __ \\( ) ( )| |  _ (  __) / __ \\ / _  |/  __)' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + ' (`-=-=-=-=-=-=-=-=-`)  ' + termcolor.WHITE + ' | | | |( (_) )| ( ) |(  ___/| (_) || (_( )| |   (  ___/( (_| |\\__  \\' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + ' (`-=-=-=-=-=-=-=-=-`)  ' + termcolor.WHITE + ' (_) (_) \\ __/ (() (_) )\\___) \\__  |(____/ (()    )\\___) ) _ _)(__(_/' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + ' (`-=-=-=-=-=-=-=-=-`)  ' + termcolor.WHITE + '         /(    (_)    (__)   ( )_| |       (_)   (__)   (__)     /(  ' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + '  (`-=-=-=-=-=-=-=-`)   ' + termcolor.WHITE + '        (__)                  \\___/                             (__) ' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + '   (`-=-=-=-=-=-=-`)' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + '     (`-=-=-=-=-`)' + termcolor.END)
	print(termcolor.YELLOW + termcolor.BOLD + '      `-=-=-=-=-`' + termcolor.END)
	print(termcolor.YELLOW + '                                   Author: ' + termcolor.WHITE + termcolor.BOLD + 'Ben Ten (@ben0xa)' + termcolor.END + termcolor.WHITE + ' - ' + termcolor.YELLOW + 'Version: ' + termcolor.WHITE + termcolor.BOLD + '0.1' + termcolor.END)
	print('')
	print(termcolor.GREEN + termcolor.BOLD + '[+]' + termcolor.END + ' Clients:')	
	if str.upper(SMB) == 'OFF':
		oncolor = termcolor.RED
	else:
		oncolor = termcolor.GREEN
	print('    SMB Client\t\t' + oncolor + termcolor.BOLD + '[' + SMB + ']' + termcolor.END)
	if str.upper(HTTP) == 'OFF':
		oncolor = termcolor.RED
	else:
		oncolor = termcolor.GREEN
	print('    HTTP Client\t\t' + oncolor + termcolor.BOLD + '[' + HTTP + ']' + termcolor.END)
	print('')
	print(termcolor.GREEN + termcolor.BOLD + '[+]' + termcolor.END + ' Generic Options:')
	print('    Domain\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + def_domain + ']' + termcolor.END)
	print('    Username\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + def_username + ']' + termcolor.END)
	print('    Password\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + def_password + ']' + termcolor.END)
	print('    Hostname\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + def_hostname + ']' + termcolor.END)
	print('    FQDN\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + def_fqdn + ']' + termcolor.END)
	print('    SMB Sleep\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + str(SMB_SLEEP) + ' seconds]' + termcolor.END)
	print('    HTTP Sleep\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + str(HTTP_SLEEP) + ' seconds]' + termcolor.END)
	print('')

class termcolor:
    WHITE = '\033[37m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RED = '\033[31m'
    END = '\033[0m'
    BOLD = '\033[1m'

class messages:
	RSP_RECVD = '%(color)s%(bold)s[%(proto)s]%(end)s Poisoned response received from %(ip)s for name %(hostname)s.'
			
class SMBClient(threading.Thread):
	def __init__(self, username, hostname):
		threading.Thread.__init__(self)
		self.username = username
		self.hostname = hostname

	def run(self):
		global def_password, smb_exit, SPLUNK, splunk_index, local_hostname
		username = self.username
		hostname = self.hostname
		while smb_exit.is_set() == False:
			smbclient.ClientConfig(username=username, password=def_password, connection_timeout=1)
			connected = False
			try:
				with smbclient.open_file(r'\\\\' + hostname + '\\share\\file.txt', mode='r') as f:
					connected = True
			except Exception as exception:
				if type(exception).__name__ == 'AccessDenied':
					try:
						drslt = subprocess.check_output('dig +short ' + hostname, shell=True).decode('utf-8')
					except:
						pass
					drslt_parts = drslt.split('\n')
					rmt_ip = 'Unknown'
					if len(drslt_parts) > 1:
						if hostname in drslt_parts[0]:
							rmt_ip = drslt_parts[1]
						else:
							rmt_ip = drslt_parts[0]

					if SPLUNK:
						event = str(time.time()) + ','
						event += 'protocol="SMB",'
						event += 'ip_address=' + rmt_ip + ','
						event += 'honey_hostname="' + hostname + '",'
						event += 'honey_username="' + username + '",'
						event += 'message="Responder activity detected!"'
						splunk_index.submit(event, sourcetype="honeycreds.service", host=local_hostname)

					logging.critical(messages.RSP_RECVD % {'color':'', 'bold':'', 'proto':'SMB', 'end':'', 'ip':rmt_ip, 'hostname':hostname})
					print(messages.RSP_RECVD % {'color':termcolor.BLUE, 'bold':termcolor.BOLD, 'proto':'SMB', 'end':termcolor.END, 'ip':rmt_ip, 'hostname':hostname})
			except:
				pass
			smbclient.reset_connection_cache()
			if smb_exit.is_set() == False:
				smb_exit.wait(SMB_SLEEP)

class HTTPClient(threading.Thread):
	def __init__(self, username, hostname):
		threading.Thread.__init__(self)
		self.username = username
		self.hostname = hostname

	def run(self):
		global def_password, http_exit, SPLUNK, splunk_index, local_hostname
		username = self.username
		hostname = self.hostname
		url = 'http://' + hostname
		while http_exit.is_set() == False:			
			try:
				hrsp = requests.get(url, auth=(username, def_password), timeout=(1,5))
				try:
					drslt = subprocess.check_output('dig +short ' + hostname, shell=True).decode('utf-8')
				except:
					pass
				drslt_parts = drslt.split('\n')
				rmt_ip = 'Unknown'
				if len(drslt_parts) > 1:
					if len(drslt_parts) > 1:
						if hostname in drslt_parts[0]:
							rmt_ip = drslt_parts[1]
						else:
							rmt_ip = drslt_parts[0]

				if SPLUNK:
					event = str(time.time()) + ','
					event += 'protocol="HTTP",'
					event += 'ip_address=' + rmt_ip + ','
					event += 'honey_hostname="' + hostname + '",'
					event += 'honey_username="' + username + '",'
					event += 'message="Responder activity detected!"'
					splunk_index.submit(event, sourcetype="honeycreds.service", host=local_hostname)

				logging.critical(messages.RSP_RECVD % {'color':'', 'bold':'', 'proto':'HTTP', 'end':'', 'ip':rmt_ip, 'hostname':hostname})
				print(messages.RSP_RECVD % {'color':termcolor.BLUE, 'bold':termcolor.BOLD, 'proto':'HTTP', 'end':termcolor.END, 'ip':rmt_ip, 'hostname':hostname})
			except:
				pass
			if http_exit.is_set() == False:
				http_exit.wait(HTTP_SLEEP)

def main():
	global smb_Thread, http_Thread, SPLUNK
	os.system('clear')
	banner()
	print(termcolor.GREEN + termcolor.BOLD + '[+]' + termcolor.END + ' Sending events...')
	username = def_domain + '\\' + def_username
	hostname = def_hostname + '.' + def_fqdn
	if str.upper(SMB) == 'ON':
		smb_Thread = SMBClient(username, hostname)
		smb_Thread.start()
	if str.upper(HTTP) == 'ON':
		http_Thread = HTTPClient(username, hostname)
		http_Thread.start()
	if SPLUNK:
		init_splunk()

if __name__ == '__main__':
	signal(SIGINT, signal_handler)
	init()
	main()
