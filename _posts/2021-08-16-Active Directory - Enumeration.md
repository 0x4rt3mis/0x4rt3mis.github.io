---
title: "Active Directory - Enumeration"
tags: [Metodologies]
categories: ActiveDirectory
mermaid: true
image: https://www.safesystems.com/wp-content/uploads/2020/04/Microsofts-LDAP-Security-Update-and-the-Impact-on-Financial-Institutions-Today-Header-Blog-Image.png
---

# Active Directory - Enumeration

Here you will find some commands to explore Active Directory and make a good Enumeration

Everything will need to know to enumerate properly it.

Hope you enjoy.

# Summary

- [Active Directory - Enumeration](#active-directory---enumeration)
- [Summary](#summary)
- [Initial Consideration](#initial-consideration)
- [Domain Enumeration](#domain-enumeration)
  - [User Enumeration](#user-enumeration)
  - [Group Enumeration](#group-enumeration)
  - [Computer Enumeration](#computer-enumeration)
  - [Domain Admins Enumeration](#domain-admins-enumeration)
  - [Enumeration of Shares](#enumeration-of-shares)
  - [Enumeration of ACLs](#enumeration-of-acls)
  - [Enumeration of OUs](#enumeration-of-ous)
  - [Domain Trusts Enumeration](#domain-trusts-enumeration)
  - [USER HUNTING Enumeration](#user-hunting-enumeration)
- [Conclusion](#conclusion)
  - [Resume](#resume)

![](https://0x4rt3mis.github.io/assets/assets/img/active-enum/enum.jpeg.png)

# Initial Consideration

Now let's start enumerating an Active Directory, which is the first step to be taken in any offensive activity.

The tool I will use for this section is PowerView.ps1, a script written in PowerShell that allows for quick and accurate enumeration of (almost) everything that exists within the AD environment!

Script download link

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

And of course, of course, I'll hide all mentions for which environment I'm enumerating, here it's just for didactic purposes!

# Domain Enumeration

Let's start and enumerate!

Logically after we have downloaded the script we should import it, with the command `Import-Module PowerView.ps1`

## User Enumeration

The command to perform user enumeration within AD environment is

```ps1
Get-NetUser | select Name
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/user.png)

And here are listed all users who are registered within Active Directory.

## Group Enumeration

The command to perform enumeration of groups within AD environment is

```ps1
Get-NetGroup | select Name
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/group.png)

And here are all groups within AD.

## Computer Enumeration

Yes, that's right, we can see all computers that are registered within the domain!
The command for this is:

```ps1
Get-NetComputer | select Name
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/computer.png)

From then on, we started to see what our possible targets are!

## Domain Admins Enumeration

The command to enumerate all Domains Admins is:

```ps1
Get-NetGroupMember "Domain Admins"
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/da.png)

## Enumeration of Shares

We can also check all available shares in AD, folders that we will have access to.

```ps1
Invoke-ShareFinder
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/share.png)

## Enumeration of ACLs

ACLs are the permissions they have within AD, in this case each Object

```ps1
Get-ObjectAcl -SamAccountName "Domain Admins"
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/acl1.png)

So we check all ACLS from all groups

```ps1
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/acl2.png)

## Enumeration of OUs

```ps1
Get-NetOU select | name
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/ou.png)

## Domain Trusts Enumeration

The idea now is to enumerate the trusts that our domain has in FOREST

```ps1
Get-NetDomainTrust
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/trust.png)

With `Get-NetForest Domain` we check all domains in the current forest,

![](https://0x4rt3mis.github.io/assets/img/active-enum/trus_domaint.png)

With the command `Get-New Forest Trust` we check the trusts of our forest

![](https://0x4rt3mis.github.io/assets/img/active-enum/trust2.png)

This is important because with this bidirectional trust we can also enumerate the other domain (outside of ours) in the case what appeared there in the command above

```ps1
Get-NetComputer -Domain domain_showed.local | select name
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/trust3.png)

These are machines accessible in another forest through the trust we have in our domain! Interesting!

## USER HUNTING Enumeration

With it we check if on any machine in the domain we have local admin access (VERY NOISY)

```ps1
Find-LocalAdminAccess
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/admin.png)

It didn't work here because I don't have administrative access on any machine with my username

Another very important function is Invoke-UserHunter, it does the same thing as Find-LocalAdminAccess

```ps1
Invoke-UserHunter
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/admin1.png)

It didn't work here because I don't have administrative access on any machine with my username

# Conclusion

A good enumeration is always of utmost importance in any environment we come across. It does not end here, there is still much more to be explored, however for an initial analysis.

## Resume

Summarizing what was done, first we must have the tool PowerView (https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1), so we can perform the enumeration.

Commands used.

```ps1
Get-NetUser | select Name
Get-NetGroup | select Name
Get-NetComputer | select Name
Get-NetGroupMember "Domain Admins"
Invoke-ShareFinder
Get-ObjectAcl -SamAccountName "Domain Admins"
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs
Get-NetOU select | name
Get-NetDomainTrust
Get-NetForestDomain
Get-NetForestTrust
Get-NetComputer -Domain domain_showed.local | select name
Find-LocalAdminAccess
Invoke-UserHunter
```

Now let's go to MSSQL server enumeration