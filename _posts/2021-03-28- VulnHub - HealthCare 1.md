---
title: "VulnHub - HealthCare 1"
tags: [Linux,Easy,Web,Gobuster,Samba]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/inicial.png)

Link: [HealthCare 1](https://www.vulnhub.com/entry/healthcare-1,522/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas abertas no servidor

> Porta 21 -> FTP

> Porta 80 -> Web

## Enumeraçã da Porta 21

Vemos que o servidor FTP não tem login anônimo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/ftp.png)

Não encontramos vulnerabilidades na versão do FTP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/ftp1.png)

## Enumeração da Porta 80

Abrimos ela pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/web.png)

Rodamos o Gobuster

```bash
gobuster dir -u http://192.168.56.141/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-big.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/gobuster.png)

Verificamos algo interessante no robots.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/robots.png)

### /all_our_e-mail_addresses

Nada de interessante aqui

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/all.png)

Nem no código fonte

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/all1.png)

### /openemr

Acessamos esse outro que pareceu um pouco mais promissor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/opene.png)

Pesquisamos por exploits para esse sistema e encontramos vários para essa versão

```bash
searchsploit OpenEMR 4.1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/opene1.png)

Não conseguimos utilizar muito bem esses exploits, então resolvi jogar uma requisição para o Burp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/burp2.png)

Apenas adicionando uma aspa no login, temos um ponto de SQLInjection

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/burp3.png)





