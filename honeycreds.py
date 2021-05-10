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
# configparser
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
import configparser
import splunklib.client as client
from datetime import datetime
from signal import signal, SIGINT

class Config:
	def __init__(self, conf_file='./honeycreds.conf'):
		config_file = configparser.RawConfigParser(allow_no_value=True)
		config_file.read(conf_file)
		self.def_username = config_file.get('general', 'def_username')
		self.def_domain = config_file.get('general', 'def_domain')
		self.def_password = config_file.get('general', 'def_password')
		self.def_fqdn = config_file.get('general', 'def_fqdn')
		self.def_hostname = config_file.get('general', 'def_hostname')
		self.def_logfile = config_file.get('general', 'def_logfile')
		self.SMB = config_file.get('protocols', 'SMB')
		self.HTTP = config_file.get('protocols', 'HTTP')
		self.SMB_SLEEP = config_file.getint('protocols', 'SMB_SLEEP')
		self.HTTP_SLEEP = config_file.getint('protocols', 'HTTP_SLEEP')
		self.SPLUNK = config_file.get('forwarders', 'SPLUNK')
		self.ELK = config_file.get('forwarders', 'ELK')
		self.SPLUNK_HOSTNAME = config_file.get('splunk', 'SPLUNK_HOSTNAME')
		self.SPLUNK_PORT = config_file.getint('splunk', 'SPLUNK_PORT')
		self.SPLUNK_USERNAME = config_file.get('splunk', 'SPLUNK_USERNAME')
		self.SPLUNK_PASSWORD = config_file.get('splunk', 'SPLUNK_PASSWORD')
		self.SPLUNK_TOKEN = config_file.get('splunk', 'SPLUNK_TOKEN')
		self.SPLUNK_INDEX = config_file.get('splunk', 'SPLUNK_INDEX')

smb_Thread = None
http_Thread = None
smb_exit = threading.Event()
http_exit = threading.Event()
splunk_service = None
splunk_index = None
local_hostname = socket.gethostname()
config = Config()

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
	global config
	log_format = ('[%(asctime)s] %(levelname)-8s %(name)-12s %(message)s')	
	logging.basicConfig(
		level=logging.CRITICAL,
		format=log_format,
		filename=(config.def_logfile)
	)
	SMB = str.upper(config.SMB)
	HTTP = str.upper(config.HTTP)

def init_splunk():
	global splunk_service, splunk_index, config	
	if config.SPLUNK_TOKEN != None:
		try:
			splunk_service = client.connect(host=config.SPLUNK_HOSTNAME, port=config.SPLUNK_PORT, splunkToken=config.SPLUNK_TOKEN)
		except:
			print('[-] Failed to Authenticate to Splunk! Check configuration settings.')
			splunk_service = None
	else:
		try:
			splunk_service = client.connect(host=config.SPLUNK_HOSTNAME, port=config.SPLUNK_PORT, username=config.SPLUNK_USERNAME, password=config.SPLUNK_PASSWORD)
		except:
			print('[-] Failed to Authenticate to Splunk! Check configuration settings.')
			splunk_service = None

	#Get or create index
	if splunk_service:
		try:
			splunk_index = splunk_service.indexes[config.SPLUNK_INDEX]
		except:
			try:
				splunk_index = splunk_service.indexes.create(config.SPLUNK_INDEX)
			except:
				print('[-] Failed to get Splunk indexes! Check configuration settings.')

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
	print(termcolor.YELLOW + '                                   Author: ' + termcolor.WHITE + termcolor.BOLD + 'Ben Ten (@ben0xa)' + termcolor.END + termcolor.WHITE + ' - ' + termcolor.YELLOW + 'Version: ' + termcolor.WHITE + termcolor.BOLD + '0.2' + termcolor.END)
	print('')
	print(termcolor.GREEN + termcolor.BOLD + '[+]' + termcolor.END + ' Clients:')	
	if str.upper(config.SMB) == 'OFF':
		oncolor = termcolor.RED
	else:
		oncolor = termcolor.GREEN
	print('    SMB Client\t\t' + oncolor + termcolor.BOLD + '[' + config.SMB + ']' + termcolor.END)
	if str.upper(config.HTTP) == 'OFF':
		oncolor = termcolor.RED
	else:
		oncolor = termcolor.GREEN
	print('    HTTP Client\t\t' + oncolor + termcolor.BOLD + '[' + config.HTTP + ']' + termcolor.END)
	print('')
	print(termcolor.GREEN + termcolor.BOLD + '[+]' + termcolor.END + ' Generic Options:')
	print('    Domain\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + config.def_domain + ']' + termcolor.END)
	print('    Username\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + config.def_username + ']' + termcolor.END)
	print('    Password\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + config.def_password + ']' + termcolor.END)
	print('    Hostname\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + config.def_hostname + ']' + termcolor.END)
	print('    FQDN\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + config.def_fqdn + ']' + termcolor.END)
	print('    SMB Sleep\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + str(config.SMB_SLEEP) + ' seconds]' + termcolor.END)
	print('    HTTP Sleep\t\t' + termcolor.YELLOW + termcolor.BOLD + '[' + str(config.HTTP_SLEEP) + ' seconds]' + termcolor.END)
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
		global config, smb_exit, splunk_index, local_hostname
		username = self.username
		hostname = self.hostname
		while smb_exit.is_set() == False:
			smbclient.ClientConfig(username=username, password=config.def_password, connection_timeout=1)
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

					if str.upper(config.SPLUNK) == 'ON' and splunk_index:
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
				smb_exit.wait(config.SMB_SLEEP)

class HTTPClient(threading.Thread):
	def __init__(self, username, hostname):
		threading.Thread.__init__(self)
		self.username = username
		self.hostname = hostname

	def run(self):
		global config, http_exit, splunk_index, local_hostname
		username = self.username
		hostname = self.hostname
		url = 'http://' + hostname
		while http_exit.is_set() == False:			
			try:
				hrsp = requests.get(url, auth=(username, config.def_password), timeout=(1,5))
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

				if str.upper(config.SPLUNK) == 'ON' and splunk_index:
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
				http_exit.wait(config.HTTP_SLEEP)

def main():
	global config, smb_Thread, http_Thread
	os.system('clear')
	banner()
	print(termcolor.GREEN + termcolor.BOLD + '[+]' + termcolor.END + ' Sending events...')
	username = config.def_domain + '\\' + config.def_username
	hostname = config.def_hostname + '.' + config.def_fqdn
	if str.upper(config.SPLUNK) == 'ON':
		init_splunk()
	if str.upper(config.SMB) == 'ON':
		smb_Thread = SMBClient(username, hostname)
		smb_Thread.start()
	if str.upper(config.HTTP) == 'ON':		
		http_Thread = HTTPClient(username, hostname)
		http_Thread.start()

if __name__ == '__main__':
	signal(SIGINT, signal_handler)
	init()
	main()
