---
title: "VulnHub - RickdiculouslyEasy 1"
tags: [Linux, Easy]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/inicial.png)

Link: [RickdiculouslyEasy](https://www.vulnhub.com/entry/rickdiculouslyeasy-1,207/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 4 portas aberta no servidor

> Porta 21 -> FTP

> Porta 22 -> SSH

> Porta 80 -> Web

> Porta 9090 -> Web?!


## Enumeração da porta 9090

Assim que acessamos a página, achamos uma flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/flag3.png)

Tentamos rodar o gobuster, sem sucesso

```bash
gobuster dir -u http://192.168.56.115:9090 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/gobuster3.png)

Então, usamos o wfuzz

```bash
wfuzz -c --hh 41766,73,3410 -t 200 -w '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' -u 'http://192.168.56.115:9090/FUZZ'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/wfuzz.png)

Bom, nada de útil...

## Enumeração da Porta 80

Primeira coisa é abrirmos a página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/web.png)

Rodamos o gobuster nela

```bash
gobuster dir -u http://192.168.56.115 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/gobuster.png)

Encontramos a página **/passwords**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/gobuster1.png)

Encontramos a flag numero 2

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/flag2.png)

Acessamos o **passwords.html**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/gobuster2.png)

Encontramos uma senha?!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/passwordhtml.png)

Acessamos o **robots.txt** também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/robots.png)

Acessamos o **cgi-bin**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/trace.png)

Execução de comandos?

Bom, vamos jogar pro Burp pra melhor trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/burp2.png)

Simm! Temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/burp3.png)

Mas não conseguimos pegar um reverse shell.. possivelmente tem algum tipo de sanitização na página web que bloqueia alguns caracteres

Vamos prosseguir na emueração, que tal enumerarmos os usuário dessa máquina? Uma vez que temos uma senhas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/tail.png)

```
RickSanchez:x:1000:1000::/home/RickSanchez:/bin/bash
Morty:x:1001:1001::/home/Morty:/bin/bash
Summer:x:1002:1002::/home/Summer:/bin/bash
```

Show, vamos seguir

## Enumeração da Porta 21

Tentamos login anonimo, conseguimos e baixamos a flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/ftp.png)

Mas vemos que não é possível vizualizar ela, isso é por causa que temos que mudar para modo binário o FTP, então acessamos novamente fazemos isso, baixamos a flag de novo e lemos ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/ftp1.png)

### Brute Force

Tentamos brute force com os usuário e a senha que temos

Com o Hydra

```bash
hydra -L users.txt -P senha.txt 192.168.56.115 ftp
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/hydra.png)

Com o Medusa (apenas para conhecimento)

```
for i in $(cat users.txt); do echo "$i:winter" >> credenciais.txt;done
for i in $(cat credenciais.txt); do echo 192.168.56.115:$i; done >> combo.txt
medusa -C combo.txt -M ftp 2> /dev/null
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/medusa.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/medusa1.png)