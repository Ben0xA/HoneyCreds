# HoneyCreds
HoneyCreds network credential injection to detect responder and other network poisoners.

# Requirements
Requires Python 3.6+ (tested on Python 3.9)
smbprotocol
cffi

# Installation
git clone https://github.com/Ben0xA/HoneyCreds.git
pip3 install -r requirements.txt

# Running
python3 honeycreds.py

# Settings
It is advised that you change these settings to best suit your environment. Note: You can use an existing account, just change the password.

Choose a legit looking username
def_username = 'honeycreds' 

This can match your current Short Domain
def_domain   = 'XQQX'

Make this whatever you want. Note: HTTP requests will send this in plaintext
def_password = 'This is a honey cred account.'

The FQDN. Leave .local at the end.
def_fqdn     = 'xqqx.local'

The hostname that DOES NOT EXIST but looks legit.
def_hostname = 'HNECRD01'

The log file and location
def_logfile  = 'honeycreds.log'

Ability to turn SMB or HTTP on or off. Set to "OFF" to turn off.
SMB = 'ON'
HTTP = 'ON'

The time to pause in seconds between requests.
SMB_SLEEP = 5
HTTP_SLEEP = 12
