---
title: "VulnHub - Silky-CTF: 0x02"
tags: [Linux, Medium]
categories: VulnHub OSWE
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/inicial.png)

Link: [Silky-CTF: 0x02](https://www.vulnhub.com/entry/silky-ctf-0x02,307/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas aberta no servidor

> Porta 80 -> Web

> Porta 22 -> SSH

## Enumeração da Porta 80

Entramos na página web pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/web.png)

Gobuster

```bash
gobuster dir -u http://192.168.56.128/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/gobuster.png)

### admin.php

Entramos no admin.php pra ver o que podemos fazer

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/admin.png)

