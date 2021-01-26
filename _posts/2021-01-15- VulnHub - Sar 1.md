---
title: "VulnHub - Sar 1"
tags: [Linux, Easy]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/inicial.png)

Link: <https://www.vulnhub.com/entry/sar-1,425/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 1 porta aberta no servidor

> Porta 80 -> Servidor Web

## Enumeração da Porta 80 (Web)

Entramos no site pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/web.png)

Rodamos o gobuster nele

```bash
gobuster dir -u http://192.168.56.110 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar/gobuster.png)

Achamos o **phpinfo.php** e o **robots.txt**