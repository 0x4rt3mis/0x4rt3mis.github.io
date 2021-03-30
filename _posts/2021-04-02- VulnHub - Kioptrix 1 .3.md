---
title: "VulnHub - Kioptrix 1.3 #4"
tags: [Linux,Easy,Web,Gobuster,SQLInjection,Linpeas,Brute Force]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/inicial.png)

Link: [Kioptrix 1.3](https://www.vulnhub.com/entry/kioptrix-level-13-4%2C25/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas abertas no servidor

> Porta 22 -> SSH

> Porta 80 -> Web

> Portas 139 e 445 -> Samba

## Enumeração da Porta 445

```bash
smbmap -H 192.168.56.146
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/smb.png)

```bash
smbclient -L 192.168.56.146
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/smb1.png)

```bash
enum4linx -a 192.168.56.146
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/smb2.png)

Não conseguimos nada na porta 445, por enquanto.

## Enumeração da Porta 80

Acessamos a página web para verificar do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/web.png)

Gobuster nela

```bash
gobuster dir -u http://192.168.56.146 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/gobuster.png)

A única coisa que chamou atenção foi o fato de aparecer essas duas pastas `robert` e `john`, possivelmente são usuários da máquina

Acessando as páginas temos umas senhas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/john.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/john1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/robert.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/robert1.png)

Ambos redirecionam para a página login

Tentamos login admin:admin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/web1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/web2.png)

# SQLinjection

Agora tentamos login apenas uma ' (aspa)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/web4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/web5.png)

Opa, mensagem de erro, pode ser que tenhamos algum tipo de SQLInjection ai para explorar

Jogamos para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp2.png)

Vamos testando os parâmetros e descobrimos que o campo vulnerável é o `password`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp3.png)

Injetamos o payload correto (após testes) para bypassar o login

```
admin'OR '1'='1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp4.png)

Agora tentamos no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp6.png)

Bom, então tentamos com o usuário robert

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp7.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp8.png)

```
Username 	: 	robert
Password 	: 	ADGAdsafdfwt4gadfga==
```

Agora com o john

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp9.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp10.png)

```
Username 	: 	john
Password 	: 	MyNameIsJohn
```

Agora temos duas senhas! Vamos tentar ssh com elas

Robert

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ssh.png)

John

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ssh1.png)

Beleza, vamos escalar privilégio agora

Verificamos que ambos shells são **restritos**, então não podemos executar todos os comandos nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ssh2.png)

Tentamos escapar essa bash restrito com o `-t /bin/bash`, o `-t /bin/sh` e o `"bash --noprofile"`, e nenhum deu certo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ssh3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ssh4.png)

# Restricted Shell

Verificando o comando `help help` vemos que o shell restrito é o `lshell`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help.png)

Pesquisamos por vulnerabilidades para ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help1.png)

Encontramos um modo fácil de se escapar dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help2.png)

https://www.aldeid.com/wiki/Lshell

```bash
echo os.system('/bin/bash')
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help3.png)

Então escapamos!

John

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help4.png)

Robert

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help5.png)

# john -> root

Verificando na página web encontramos a senha do mysql, entramos nele e não conseguimos extrair nenhuma senha a mais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/sql.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/sql1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/sql2.png)

Contudo com o comando abaixo verificamos que o mysql está sendo executado como root, ou seja, podemos escalar privilégios por ai

```bash
ps -ef | grep mysql
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/sql3.png)




