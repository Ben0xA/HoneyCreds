# HoneyCreds
HoneyCreds network credential injection to detect responder and other network poisoners.
![HoneyCreds Screenshot](/honeycreds_screenshot.png?raw=true "HoneyCreds Screenshot")

# Requirements
```
Requires Python 3.6+ (tested on Python 3.9)
smbprotocol
cffi
splunk-sdk
```

# Installation
```
git clone https://github.com/Ben0xA/HoneyCreds.git
cd HoneyCreds
pip3 install -r requirements.txt
```

# Running
```
python3 honeycreds.py
```

# Settings
It is advised that you change these settings to best suit your environment. Note: You can use an existing account, just change the password.

Choose a legit looking username
```python
def_username = 'honeycreds' 
```

This can match your current Short Domain
```python
def_domain   = 'XQQX'
```

Make this whatever you want. Note: HTTP requests will send this in plaintext
```python
def_password = 'This is a honey cred account.'
```

The FQDN. Leave .local at the end.
```python
def_fqdn     = 'xqqx.local'
```

The hostname that DOES NOT EXIST but looks legit.
```python
def_hostname = 'HNECRD01'
```

The log file and location
```python
def_logfile  = 'honeycreds.log'
```

Ability to turn SMB or HTTP on or off. Set to "OFF" to turn off.
```python
SMB = 'ON'
HTTP = 'ON'
```
The time to pause in seconds between requests.
```python
SMB_SLEEP = 5
HTTP_SLEEP = 12
```
