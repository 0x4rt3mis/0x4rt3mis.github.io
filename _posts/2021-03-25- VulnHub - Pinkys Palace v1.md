---
title: "VulnHub - Pinkys Palace v1"
tags: [Linux, Medium]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/inicial.png)

Link: [Pinkys Palace v1](https://www.vulnhub.com/entry/pinkys-palace-v1,225/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/nmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/nmap2.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 3 portas abertas no servidor

> Portas 8080 e 31337 -> Web

> Porta 64666 -> SSH

## Enumeração da Porta 8080

Abrimos pra ver do que se trata

É uma página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/web.png)

Rodamos o Gobuster pra ver se encontramos algo

```bash
gobuster dir -u http://192.168.56.138:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/gobuster.png)

Não conseguimos ver pelo Gobuster pela mensagem de erro que ele traz, vamos tentar fazer pelo Wfuzz

```bash
wfuzz -t 200 -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hc 403 http://192.168.56.138:8080/FUZZ
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/wfuzz.png)

Nada...

## Enumeração da Porta 31337

Abrimos pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/web1.png)

Rodamos o Gobuster pra ver se encontramos algo

```bash
gobuster dir -u http://192.168.56.137:31337/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/gobuster1.png)

Não conseguimos ver pelo Gobuster pela mensagem de erro que ele traz, vamos tentar fazer pelo Wfuzz

```bash
wfuzz -t 200 -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hc 400 http://192.168.56.138:31337/FUZZ
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/wfuzz1.png)
