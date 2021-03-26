---
title: "VulnHub - Tiki 1"
tags: [Linux,Easy,Web,Gobuster,Samba]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/inicial.png)

Link: [Tiki 1](https://www.vulnhub.com/entry/tiki-1,525/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas abertas no servidor

> Porta 22 -> SSH

> Porta 80 -> Web

> Portas 139 e 445 -> Samba

## Enumeração da Porta 80

Primeira coisa é abrirmos o site web que está sendo disponibilizado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/web.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/web1.png)

Nada de interessante

Gobuster nele

```bash
gobuster dir -u http://192.168.56.140 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/gobuster.png)

Verificamos o robots.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/robots.png)

## /tiki

Acessamos o diretório encontrado /tiki

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/tiki.png)

Pelo que parece é uma wiki

Verificamos sua versão, e é a 21.1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/tiki1.png)

Procuramos por exploits para ela

Encontramos uma de bypass de autenticação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/tiki2.png)

Executamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/tiki3.png)

Jogamos a requisição para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/tiki4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/tiki5.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/tiki6.png)

Removemos a senha e clicamos em Send

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/tiki7.png)

Atualizamos a página e estamos logados como admin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/tiki8.png)

Começamos a pesquisar e encontramos credenciais salvas dentro do painel

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/cred.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/cred1.png)

# silky -> root

Agora logamos via SSH na máquina com essas credenciais, e damos o comando `su root` e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/ssh.png)

Pegamos a flag de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/flag.png)

# Bônus

Acessamos o smb dele e baixamos um arquivo Notes.txt, onde está uma senha de admin

```bash
smbclient -L //192.168.56.140
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/smb.png)

```bash
smbclient //192.168.56.140/Notes
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tiki1/smb1.png)

Bom, essa é a senha do admin, esse é outro modo de se entrar nessa máquina