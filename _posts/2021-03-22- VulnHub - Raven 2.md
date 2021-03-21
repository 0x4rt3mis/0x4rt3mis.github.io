---
title: "VulnHub - Raven 2"
tags: [Linux, Medium]
categories: VulnHub OSWE
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/inicial.png)

Link: [Raven 2](https://www.vulnhub.com/entry/raven-2,269/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas aberta no servidor

> Porta 22 -> SSH

> Porta 80 -> Web

> Porta 111 -> RPC

> Porta 44452 -> ?!

## Enumeração da Porta 80

Abrimos pra ver do que se trata

Verificamos que é uma página de login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/web.png)

No código fonte não verificamos nada de estranho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/web1.png)

O que chamou atenção é o fato de não dar mensagem nenhuma de erro quando tentamos algum tipo de login e senha

Rodamos o Gobuster pra ver se encontramos algo

```bash
gobuster dir -u http://192.168.56.135/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/gobuster.png)
