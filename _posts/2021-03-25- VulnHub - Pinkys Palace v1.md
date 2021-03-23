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

> Porta 8080 -> Web

> Porta 31337 -> Proxy?! Web?!

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

Bom, de cara assim não encontramos nada, mas partindo da premissa que isso é um proxy, devemos utilizar ele como proxy

Com o curl podemos verificar isso

```bash
curl --proxy http://192.168.56.138:31337 127.0.0.1:8080
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy.png)

Setamos o proxy para essa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy1.png)

Agora acessamos e vemos que realmente temos outra página web ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy2.png)

### Gobuster Proxy

Agora fazemos o fuzzing de diretórios através de um proxy

```bash
gobuster dir -u http://127.0.0.1:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --proxy http://192.168.56.138:31337
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy3.png)

Opa, achamos um novo diretório

### /littlesecrets-main

Acessamos ele para ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy4.png)

Campo de login e senha, a primeira coisa que pensamos em fazer é alguma tentativa de bypassar esse login e senha

Fazemos um novo GoBuster dentro dele

```bash
gobuster dir -u http://127.0.0.1:8080/littlesecrets-main -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --proxy http://192.168.56.138:31337 -x php
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/gob.png)

Acessamos o login.php que é a página de login mesmo, e o `logs.php` que nos chamou mais atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/gob1.png)

Estranho, aqui mostra o user, pass e o User-Agent utilizado...

Devemos fazer um SQL Injection nele, desta cheatsheet tentamos encontrar um que nos serve

https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy5.png)

Enviamos a requisição para o Burp

Para isso configuramos o **Upstream Proxy**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/burp.png)

Enviamos para o burp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/burp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/burp2.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/burp3.png)

Depois de muita tentativa, sem sucesso de fazermos algum tipo de sqlinjection com o usuário e senha, passamos a tentar com o User-Agent, que também aparece no log, a grande questão aqui é que temos um SQLi Blind, ou seja, não vemos a saída de erro, isso deixa o trabalho um pouco mais difícil de se conseguir realizar.

