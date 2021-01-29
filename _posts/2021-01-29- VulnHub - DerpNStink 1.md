---
title: "VulnHub - DerpNStink 1"
tags: [Linux, Easy]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/inicial.png)

Link: [EVM](https://www.vulnhub.com/entry/evm-1,391/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas aberta no servidor

> Porta 21 -> FTP

> Porta 22 -> SSH

> Porta 80 -> Web

## Enumeração da Porta 21

Tentamos login anonimo, sem sucesso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/ftp.png)

Pesquisamos por exploit para a versão 3.0.2 do vsFTPD, sem sucesso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/ftp1.png)

Vamos prosseguir

## Enumeração da Porta 80

Primeira coisa é abrirmos a página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/web.png)

Encontramos uma flag?! Lá no código fonte da página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/web2.png)

E deixar o gobuster fazendo seu serviço

```bash
gobuster dir -u http://192.168.56.114 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/gobuster.png)

Encontramos várias páginas

```
/weblog (Status: 301)
/php (Status: 301)
/css (Status: 301)
/js (Status: 301)
/javascript (Status: 301)
/temporary (Status: 301)
/server-status (Status: 403)
/robots.txt (Status: 200)
```

No nmap já vimos que temos duas entradas pro **robots.txt**, confirmamos isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/web3.png)

Vamos lá

### /php/

Acessamos, e deu acesso negado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/php.png)

Gobuster nele

```bash
gobuster dir -u http://192.168.56.114/php/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/gobuster1.png)

Acessamos o /phpmyadmin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/php1.png)

Show, encontramos isso... vamos prosseguir

### /temporary/

Acessamos, e deu acesso 'try harder'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/temporary.png)

Gobuster nele

```bash
gobuster dir -u http://192.168.56.114/temporary/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/gobuster2.png)

Nada de importante... vamos para o ultimo que interessa, o /weblog

### /weblog/

Acessamos ele pelo navegador

E a primeira coisa que chamou atenção foi o fato dele resolver o IP para o nome

**http://192.168.56.114/weblog/**

Para

**http://derpnstink.local/weblog/**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/weblog.png)

Consequentemente ele não vai achar, temos que colocar no nosso /etc/hosts a entrada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/hosts.png)

Agora ele achou! Pq conseguiu resolver o nome corretamente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/weblog1.png)

Vamos verificar no BurpSuite como está sendo essa requisição pra melhor entender isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/burp1.png)

Jogamos para o repeater e alteramos o HOST para o IP mesmo, pra ver o tratamento dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/burp2.png)

Verificamos na resposta (após dar Follow Redirection) algo estranho

Ele fala de um **slideshow-gallery** com um shell.php lá, mas não tem nada... bom, vamos prosseguir

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/gobuster4.png)

Gobuster nele pra não perder o costume também

```bash
gobuster dir -u http://derpnstink.local/weblog/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/gobuster3.png)

Verificamos que é um WordPress que está sendo executado ai!

#### Wpscan

Iniciamos a enumeração do WordPress

```bash
wpscan --url http://derpnstink.local/weblog/ --enumerate u
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/wpscan.png)

Encontramos dois usuários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/wpscan1.png)

Realizamos um BruteForce nesses dois usuários

```bash
wpscan --url http://derpnstink.local/weblog/ -U users.txt -P senhas.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/wpscan2.png)

Encontramos a senha padrão do admin, que é admin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/wpscan3.png)

Também encontramos um plugin desatualizado... Bom ponto de vulnerabilidade

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/wpscan4.png)