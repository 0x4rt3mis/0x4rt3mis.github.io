---
title: "Active Directory - PSSession"
tags: [Metodologies]
categories: ActiveDirectory
mermaid: true
image: https://www.safesystems.com/wp-content/uploads/2020/04/Microsofts-LDAP-Security-Update-and-the-Impact-on-Financial-Institutions-Today-Header-Blog-Image.png
---

# Active Directory - PSSession

Here you will find some commands to explore Active Directory with PSSession

Commands linked to pssession with powershell.

Commands to get other boxes, commands to transfer files...

Hope you enjoy.

# Summary

- [Active Directory - PSSession](#active-directory---pssession)
- [Summary](#summary)
- [Initial Consideration](#initial-consideration)
- [Checking Connection](#checking-connection)
- [Enter the Session](#enter-the-session)
- [Conclusion](#conclusion)
- [Commands Used](#commands-used)

![](https://0x4rt3mis.github.io/assets/img/active-enum/pssesion.png)

# Initial Consideration

Well, now let's use `PSSession` to enter other sections and with that explore machine too!

But what is PSSESION?

*Specifies a Windows PowerShell session (PSSession) to be used for the interactive session. This parameter takes a session object.*

In other words, a new section, like an 'ssh'.

# Checking Connection

We must check which machines have administrator access with the current user, as only on them will we be able to perform PPSession
The command to test connectivity is this

```ps1
$computers=( Get-WmiObject -Namespace root\directory\ldap -Class ds_computer | select  -ExpandProperty ds_cn)
foreach ($computer in $computers) { (Get-WmiObject Win32_ComputerSystem -ComputerName $computer ).Name }
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/pssesion1.png)

# Enter the Session

Well, now that we know we have connectivity, let's test the connection and enter the section!

```ps1
Invoke-Command -Scriptblock {ipconfig} -ComputerName box_with_acess
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/pssesion2.png)

We created a new section with `New-PSSession`

```ps1
$sess = New-PSSession -ComputerName box_with_access
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/pssesion3.png)

Here it is! Now we just enter the section

```ps1
Enter-PSSession -Session $sess
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/pssesion4.png)

Note: With `-File Path` we can insert scripts directly inside the section
For example:

```ps1
Invoke-Command -FilePath "C:\Users\script.ps1" -session $sess
```

# Conclusion

We now check the usefulness of PSSession in an offensive environment, every machine we get administrator access will be able to remote psession!

# Commands Used

```ps1
$computers=( Get-WmiObject -Namespace root\directory\ldap -Class ds_computer | select  -ExpandProperty ds_cn)
foreach ($computer in $computers) { (Get-WmiObject Win32_ComputerSystem -ComputerName $computer ).Name }
Invoke-Command –Scriptblock {ipconfig} -ComputerName máquina_com_acesso
$sess = New-PSSession -ComputerName máquina_com_acesso
Enter-PSSession -Session $sess
Invoke-Command -FilePath "C:\Users\script.ps1" -session $sess
```