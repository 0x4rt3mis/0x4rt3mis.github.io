---
title: "VulnHub - Homeless 1"
tags: [Linux, Medium]
categories: VulnHub OSWE
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/inicial.png)

Link: [Homeless 1](https://www.vulnhub.com/entry/homeless-1,215/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 2 portas aberta no servidor

> Porta 80 -> Web

> Porta 22 -> SSH

## Enumeração da Porta 80

Abrimos pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/web.png)

Gobuster nela

```bash
gobuster dir -u http://192.168.56.130/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/gobuster.png)

## robots.txt

Acessamos o robots.txt pra ver o que podemos tirar dai

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/web1.png)

Bom... sabemos que esse não é o path real da pasta... e não temos mais nada de dica, então continuamos a enumerar a máquina

Olhando novamente o código fonte da página, verificamos algo interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/web2.png)

Encontramos um aviso pra ler com atenção e um user agent... Isso não é normal de aparecer na página web

## BurpSuite

Jogamos a requisição para o BurpSuite para melhor trabalharmos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/burp.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/burp1.png)

Verificamos que conseguimos injetar qualquer coisa que quisermos no User Agent que ele vai ler lá no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/burp2.png)


