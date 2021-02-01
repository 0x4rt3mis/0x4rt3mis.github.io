---
title: "VulnHub - Breach 1"
tags: [Linux, Medium, Wpscan, Gobuster, Wfuzz, Exiftool, Binwalk, FTP, Wfuzz User Agent, Wfuzz Brute Force, Crunch, Fcrackzip, Wordpress, Magic Number, Find]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/inicial.png)

Link: [Breach 1](https://www.vulnhub.com/entry/breach-1,152/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/nmap.png)

### Explicação de cada parâmetro do Nmap

> -Pn --> Já considera o host ativo

### Verificamos que temos todas?! portas abertas

?!

## Enumeração da Porta 80

Acessamos ela no navegador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/web.png)

Rodamos o gobuster

```bash
gobuster dir -u http://192.168.110.140 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/images.png)

Realmente são somente imagens...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/ima.png)

Clicamos na foto da página inicial e somos redirecionados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/ini.png)

Clicamos novamente na foto e somos redirecionados para outra página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/ini1.png)

Ali diz para olharmos o código fonte, nessa página não há nada, qnd clicamos no Start Here somos redirecionados para a página inicial, olhando no código fonte da página inicial, temos:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/fonte.png)

Que significa

```bash
echo "Y0dkcFltSnZibk02WkdGdGJtbDBabVZsYkNSbmIyOWtkRzlpWldGbllXNW5KSFJo" | base64 -d | base64 -d
pgibbons:damnitfeel$goodtobeagang$ta
```

Paraceu credenciais...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/fonte1.png)

Clicamos em Employee Portal

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/emp.png)

Pelo visto é um CMS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/emp1.png)

## Impress CMS

Tentamos logar com a senha encontrada, e conseguimos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/log.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/log1.png)

Olhando na caixa de email, encontramos algo interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/email.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/email1.png)

### Java KeyStore

Baixamos o arquivos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/email2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/email3.png)

Verificamos que é uma chave... não temos ela ainda pra poder verificar o conteúdo do arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/key.png)

Em outro e-mail ele fala sobre informações sensíveis no portal do admin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/email4.png)

### Arquivo PCAP

Pesquisando encontramos algo interessante no portal

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/pass.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/pass1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach1/pass2.png)