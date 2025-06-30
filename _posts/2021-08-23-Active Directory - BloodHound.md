---
title: "Active Directory - BloodHound"
tags: [Metodologies]
categories: ActiveDirectory
mermaid: true
image: https://www.safesystems.com/wp-content/uploads/2020/04/Microsofts-LDAP-Security-Update-and-the-Impact-on-Financial-Institutions-Today-Header-Blog-Image.png
---

# Active Directory - BloodHound

Here you will find some commands to explore Active Directory.

Commands linked to BloodHound. An excellent tool to enumerate Active Directory.

Hope you enjoy.

# Summary

- [Active Directory - BloodHound](#active-directory---bloodhound)
- [Summary](#summary)
- [Initial Consideration](#initial-consideration)
- [Setting Up the BloodHound](#setting-up-the-bloodhound)
- [BloodHound Ingestor](#bloodhound-ingestor)
- [Checking the Graph](#checking-the-graph)
- [Conclusion](#conclusion)

![](https://0x4rt3mis.github.io/assets/img/active-enum/blood.png)

# Initial Consideration

BloodHound is a single page Javascript web application, built on top of Linkurious, compiled with Electron, with a Neo4j database fed by a C# data collector.

BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment.

BloodHound is developed by @_wald0, @CptJesus, and @harmj0y.

# Setting Up the BloodHound

It's instalation is really simple.

Just follow [TUTORIAL](https://stealingthe.network/quick-guide-to-installing-bloodhound-in-kali-rolling/)

Resuming, execute the command `apt-get install bloodhound` it'll automatically usntall everything. Then get into the `neo4j` and change the BloodHound password.

# BloodHound Ingestor

To verify it we must use one Ingestor, one script or exe.

[SharpHound.ps1](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)

After download it, put it on the box and execute

```ps1
Invoke-Bloodhound -CollectionMethod All,loggedon
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/blood1.png)

It's going to generate a .zip file.

# Checking the Graph

With this zip on your hand, put it on the Kali and start `neo4j console`

![](https://0x4rt3mis.github.io/assets/img/active-enum/blood2.png)

Then, start the `bloodhound`

![](https://0x4rt3mis.github.io/assets/img/active-enum/blood3.png)

Just drag and drop the .zip file on the session


![](https://0x4rt3mis.github.io/assets/img/active-enum/blood4.png)

Now, you start to verify the domain

![](https://0x4rt3mis.github.io/assets/img/active-enum/blood5.png)

# Conclusion

BloodHound is a extremelly powerfull tool to have on your box. But, don't depends on just this tool. You need to know what you are doing, BloodHound is extremelly noisy on the network.