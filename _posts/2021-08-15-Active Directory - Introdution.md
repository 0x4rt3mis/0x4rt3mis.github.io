---
title: "Active Directory - Introdution"
tags: [Metodologies]
categories: ActiveDirectory
mermaid: true
image: https://www.safesystems.com/wp-content/uploads/2020/04/Microsofts-LDAP-Security-Update-and-the-Impact-on-Financial-Institutions-Today-Header-Blog-Image.png
---

# Active Directory - Introdution

Here you will find some explanations about Active Directory.

The ideia of this post is to clarify some basic concepts of AD.

Hope you enjoy!

# Summary

- [Active Directory - Introdution](#active-directory---introdution)
- [Summary](#summary)
- [Initial Consideration](#initial-consideration)
  - [What is Active Directory?](#what-is-active-directory)
  - [How it Works?](#how-it-works)
    - [User's Perspective](#users-perspective)
    - [Technical Perspective](#technical-perspective)
  - [Active Directory Infrastructure](#active-directory-infrastructure)
    - [Logical Structure of Active Directory (AD)](#logical-structure-of-active-directory-ad)
      - [Objects](#objects)
      - [Organizational Units](#organizational-units)
      - [Domains, Trees and Forests](#domains-trees-and-forests)
    - [Active Directory Physical Structure](#active-directory-physical-structure)
      - [Domain Controllers - DC](#domain-controllers---dc)
      - [Sites](#sites)
- [Conclusion](#conclusion)

![](https://0x4rt3mis.github.io/assets/img/active-intro/active.png)

# Initial Consideration

Let's clarify some more basic explanations.

## What is Active Directory?

It's what Windows uses to control Windows' own networks, everything in AD is objects. It centralizes everything in order to manage the network more "safely". In a way, it's another world inside Microsoft.

Active Directory (AD) is a Microsoft tool used for managing network users, called a directory service. A directory is nothing more than a database containing information about an organization's users, such as name, login, password, title, profile, and so on.

As we can see in the image below it `centralizes` everything inside the network.

![](https://0x4rt3mis.github.io/assets/img/active-intro/active1.png)

A haven for network managers not? To a certain extent yes, however at least for me it is quite complex to implement and really understanding how it works in depth can take years.

Some of the main features of AD are:

```
Centralized authentication
Controlled security level
Facilitates Delegation of Administrative Tasks
Makes access management efficient
Provides an index of resources on the network
Subdivision of domains into logical units
Provides data replication capabilities
Facilitates the assignment and maintenance of multiple domains
DNS-based naming system unification
Facilitates the implementation of usage policies (Group Policies)
```

## How it Works?

Okay, how does it work?

### User's Perspective

From the users' perspective, AD works so that they can access the resources available on the network. For this, they just have to log in once in the local network environment (usually, when starting the operating system).

When the user types his login and password, AD checks if the information provided by users is valid, and if so, performs authentication. AD is organized in a hierarchical way, using domains.

### Technical Perspective

The relevant information that is normally stored in AD basically includes:

```
user contact data, printer queue information, and specific desktop or network configuration data.
```

The "Active Directory data Store" contains all directory information, such as information about users, computers, groups, other objects and objects that users can access, as well as network components. It allows full and controlled access management.

Directories are used to manage software packages, files, and end-user accounts within organizations. The administrator uses the tree and forest concepts of AD and does not need to visit desktops individually.

## Active Directory Infrastructure

And how is it structured?

### Logical Structure of Active Directory (AD)

The logical structure is divided in order to facilitate the management of objects / account records for network resources within the organization.

#### Objects

These are network resources managed by AD.

Objects are part of the logical structure of AD. The main purpose of this tool is to help the network administrator with the management of network resources. For this, AD allows the administrator to register resources in the form of directory objects. Each object type/class corresponds to an administered resource type.

Object Types in Active Directory:

```
Users
Shared Folder
User Groups
Organizational Units
Computers
Printers
Contacts
```

![](https://0x4rt3mis.github.io/assets/img/active-intro/active2.png)

#### Organizational Units

It is a type of directory object contained in domains to which User Group Policy settings can be assigned or administrative authority delegated.

Organizational Units are part of the logical structure of AD. In Active Directory Administration, an Organizational Unit (OU) is a type of directory object contained within domains to which you can assign User Group Policy settings or delegate administrative authority (the OU is the smallest scope or smallest unit to which you can assign these settings).

This feature facilitates the work of the Network Administrator who manages the configuration and use of accounts and resources based on the organizational model of the company in which he works.

#### Domains, Trees and Forests

*Domain:* is a naming for a resource family. The domain is the main functional unit of the logical structure of Active Directory.

*Tree:* this is a hierarchical organization of one or more Domains. All domains share information and resources in the tree, where roles are unique.

*Forest:* is a set of trees. The use of forests is quite common in groups of companies, where each of the companies in the group maintains an identity autonomy in relation to the others.

### Active Directory Physical Structure

It basically consists of:

```
domain controllers
 Sites
```

The components responsible for optimizing network traffic, maintaining security in physical locations, and providing resources that are utilized in a logical perspective.

#### Domain Controllers - DC

It is a server running AD DS: Active Directory Domain Services. A DC runs Active Directory and stores the AD base, as well as replicates this base with other DC's.

AD DS maintains a database of information about network resources and directory-enabled application-specific data. In other words, it is AD DS that stores the AD logical structure data.

Access management is made possible by the capabilities provided by AD DS through login authentication and access control to resources in the directory:

```
Administrators can manage directory and organization data across their entire network;
Network users can use a single login to access resources anywhere on the network, as per settings previously established by administrators.
```

#### Sites

A site is the physical location of your network infrastructure, such as a local area network (LAN). In AD DS, a site object represents aspects of the physical site that can be managed, specifically, replication of directory data between domain controllers.

Site objects are typically used by the network administrator to:

```
Create new sites
Delegate control over sites using Group Policy and permissions
```

At each site there is an NTDS Site Settings object that identifies the Intersite Topology Designer (ISTG). The ISTG is the domain controller in the site that generates the connection objects for domain controllers in different sites and performs advanced replication management functions.

# Conclusion

Well, it was possible to have a very nice overview of what Active Directory is and to be sure that it is an excellent tool when well implemented and used by the IT staff of any organization, but as we know, not everything is wonderful, now let's go start checking how we can exploit it to gain access within the environment!