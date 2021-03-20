---
title: "VulnHub - Ted 1"
tags: [Linux, Medium]
categories: VulnHub OSWE
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted1/inicial.png)

Link: [Ted 1](https://www.vulnhub.com/entry/seattle-v03,145/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted1/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted1/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 2 portas aberta no servidor

> Porta 80 -> Web

## Enumeração da Porta 80

Abrimos pra ver do que se trata

Verificamos que é uma página de login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/web.png)

No código fonte não verificamos nada de estranho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/web1.png)

O que chamou atenção é o fato de não dar mensagem nenhuma de erro quando tentamos algum tipo de login e senha

Rodamos o Gobuster pra ver se encontramos algo

```bash
gobuster dir -u http://192.168.56.134/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/gobuster.png)

Bom, verificamos que o site faz algum mecanismo de autenticação misturando php com html, temos que arranjar um jeito de burlar isso...

Jogamos a requisição do login para o BurpSuite para ver como ela funciona

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/burp2.png)

Ele está fazendo uma requisição POST para o authenticate.php

A saída que temos é essa:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/burp3.png)

Ele diz que o hash não está certo?! Se tentamos com outro usuário, ele da usuário incorreto, ou seja, temos que fazer isso com o usuário admin mesmo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/burp4.png)

Geramos um hash então pra testarmos

https://www.pelock.com/products/hash-calculator

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/hash.png)

Md5

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/burp5.png)

Sha1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/burp6.png)

Sha256

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-ted/burp7.png)

Opa, com o hash **8C6976E5B5410415BDE908BD4DEE15DFB167A9C873FC4BB8A81F6F2AB448A918 - admin**, que é um `sha256` ele não mostrou mensagem de erro!



