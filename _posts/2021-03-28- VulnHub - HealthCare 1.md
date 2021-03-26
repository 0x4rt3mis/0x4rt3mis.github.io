---
title: "VulnHub - HealthCare 1"
tags: [Linux,Easy,Web,Gobuster,FTP,SQLInjection]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/inicial.png)

Link: [HealthCare 1](https://www.vulnhub.com/entry/healthcare-1,522/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas abertas no servidor

> Porta 21 -> FTP

> Porta 80 -> Web

## Enumeraçã da Porta 21

Vemos que o servidor FTP não tem login anônimo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/ftp.png)

Não encontramos vulnerabilidades na versão do FTP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/ftp1.png)

## Enumeração da Porta 80

Abrimos ela pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/web.png)

Rodamos o Gobuster

```bash
gobuster dir -u http://192.168.56.141/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-big.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/gobuster.png)

Verificamos algo interessante no robots.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/robots.png)

### /all_our_e-mail_addresses

Nada de interessante aqui

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/all.png)

Nem no código fonte

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/all1.png)

### /openemr

Acessamos esse outro que pareceu um pouco mais promissor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/opene.png)

Pesquisamos por exploits para esse sistema e encontramos vários para essa versão

```bash
searchsploit OpenEMR 4.1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/opene1.png)

Não conseguimos utilizar muito bem esses exploits, então resolvi jogar uma requisição para o Burp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/burp2.png)

Apenas adicionando uma aspa no login, temos um ponto de SQLInjection

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/burp3.png)

Bom, mais um `Blind SQLInjection`

Vamos usar o `sqlmap`, não consegui explorar ela manualmente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/req.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/req1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/req2.png)

Conseguimos duas senhas

```
ackbar:admin
medical:medical
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/req3.png)

Logamos com o usuário `medical`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/ack.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/ack1.png)

Não conseguimos explorar muita coisa por ai

## FTP Upload

Então acessamos o FTP pra fazer o upload de um reverse shell e chamar no browser

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/ack2.png)

Acessamos uma página que temos permissão de escrita e fazemos o upload

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/ack3.png)

Testamos no navegador e temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/ack4.png)

Agora pegamos um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/ack5.png)

Agora escalamos para o usuário medical

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/ack6.png)

# medical -> root

Agora vamos escalar privilégio para root da máquina

Rodamos o linpeas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/lin.png)

Passamos pra nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/lin1.png)

Rodamos na máquina virtual

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/lin2.png)

Encontramos alguns binários não padrão sendo executado com permissões de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/lin3.png)

Também podemos ver por aqui

```bash
find / -perm -4000 2>/dev/null
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/lin4.png)

Esse `/usr/bin/healthcare` chamou a atenção

Vemos que ele roda uma sequência de binários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/lin5.png)

Bom, vamos tentar fazer um `PATH HIJACKING`

Primeira coisa é verificar qual é nosso PATH

```bash
echo $PATH
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/lin6.png)

Agora criamos nosso "binário"

```
echo '#!/bin/sh' >> ifconfig
echo '/bin/sh' >> ifconfig
chmod +x ifconfig
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/lin7.png)

Alteramos nosso PATH

```
export PATH=`pwd`:$PATH
echo $PATH
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/lin8.png)

Agora executamos o `healthcheck` e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/lin9.png)

Pegamos as flags

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/flag.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-healthcare1/flag1.png)
