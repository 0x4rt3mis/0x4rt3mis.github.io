---
title: "Port Forwading"
tags: [Metodologies]
categories: Metodology
mermaid: true
image: https://www.technewstoday.com/wp-content/uploads/2022/06/port-forwarding-not-working.jpg
---

# Port Forwading

Here I'll show some examples of how to perfrom a good port forwading with different tools.

# Summary

- [Port Forwading](#port-forwading)
- [Summary](#summary)
- [Port Forwading Examples](#port-forwading-examples)
  - [Chisel](#chisel)
    - [Simple Port Forwading](#simple-port-forwading)
    - [Socks Proxys Chisel](#socks-proxys-chisel)
  - [Mkfifo](#mkfifo)

# Port Forwading Examples

Let's jump in.

## Chisel

https://github.com/jpillora/chisel

### Simple Port Forwading

Command on the Host Box to receive the connection on my local port 8000

```
.\chisel.exe server --host 10.10.16.117 --port 8000 --reverse
```

On Attacker Box to send the connection to the port 8000 of the Host Box

```
.\chisel.exe client 10.10.16.117:8000 R:14148:127.0.0.1:14147 - (This case the port 14148 will be open on the host box to receive the connectio on 14147)
```

### Socks Proxys Chisel

Host Box

```
.\chisel.exe server --host 10.10.16.117 --port 8000 --reverse
```

Attacker box, must configure the proxychains

```  
.\chisel.exe client 10.10.16.117:8000 R:socks
```

## Mkfifo

```
cd /tmp
mkfifo fifo
cat /tmp/fifo | nc localhost 5901 | nc -l 5904 > /tmp/fifo
```

Port 5904 will receive the output from local 5901.