---
title: "VulnHub - Pinkys Palace v1"
tags: [Linux, Medium]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/inicial.png)

Link: [Pinkys Palace v1](https://www.vulnhub.com/entry/pinkys-palace-v1,225/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/nmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/nmap2.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 3 portas abertas no servidor

> Porta 8080 -> Web

> Porta 31337 -> Proxy?! Web?!

> Porta 64666 -> SSH

## Enumeração da Porta 8080

Abrimos pra ver do que se trata

É uma página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/web.png)

Rodamos o Gobuster pra ver se encontramos algo

```bash
gobuster dir -u http://192.168.56.138:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/gobuster.png)

Não conseguimos ver pelo Gobuster pela mensagem de erro que ele traz, vamos tentar fazer pelo Wfuzz

```bash
wfuzz -t 200 -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hc 403 http://192.168.56.138:8080/FUZZ
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/wfuzz.png)

Nada...

## Enumeração da Porta 31337

Abrimos pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/web1.png)

Rodamos o Gobuster pra ver se encontramos algo

```bash
gobuster dir -u http://192.168.56.137:31337/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/gobuster1.png)

Não conseguimos ver pelo Gobuster pela mensagem de erro que ele traz, vamos tentar fazer pelo Wfuzz

```bash
wfuzz -t 200 -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hc 400 http://192.168.56.138:31337/FUZZ
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/wfuzz1.png)

Bom, de cara assim não encontramos nada, mas partindo da premissa que isso é um proxy, devemos utilizar ele como proxy

Com o curl podemos verificar isso

```bash
curl --proxy http://192.168.56.138:31337 127.0.0.1:8080
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy.png)

Setamos o proxy para essa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy1.png)

Agora acessamos e vemos que realmente temos outra página web ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy2.png)

### Gobuster Proxy

Agora fazemos o fuzzing de diretórios através de um proxy

```bash
gobuster dir -u http://127.0.0.1:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --proxy http://192.168.56.138:31337
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy3.png)

Opa, achamos um novo diretório

### /littlesecrets-main

Acessamos ele para ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy4.png)

Campo de login e senha, a primeira coisa que pensamos em fazer é alguma tentativa de bypassar esse login e senha

Fazemos um novo GoBuster dentro dele

```bash
gobuster dir -u http://127.0.0.1:8080/littlesecrets-main -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --proxy http://192.168.56.138:31337 -x php
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/gob.png)

Acessamos o login.php que é a página de login mesmo, e o `logs.php` que nos chamou mais atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/gob1.png)

Estranho, aqui mostra o user, pass e o User-Agent utilizado...

Devemos fazer um SQL Injection nele, desta cheatsheet tentamos encontrar um que nos serve

https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/proxy5.png)

Enviamos a requisição para o Burp

Para isso configuramos o **Upstream Proxy**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/burp.png)

Enviamos para o burp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/burp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/burp2.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/burp3.png)

Depois de muita tentativa, sem sucesso de fazermos algum tipo de sqlinjection com o usuário e senha, passamos a tentar com o User-Agent, que também aparece no log, a grande questão aqui é que temos um SQLi Blind, ou seja, não vemos a saída de erro, isso deixa o trabalho um pouco mais difícil de se conseguir realizar.

# User-Agent Blind SQLinjection

Encontramos um bom ponto de referência para fazermos o SQLinjection nesse User-Agent

https://sechow.com/bricks/docs/content-page-4.html

Vamos lá, tentar explicar cada passo. Vamos ir alterando o User-Agent e ir verificando no log.php as alterações, se foram efetivas ou não.

```
User-Agent: Mozilla/5.0 (Windows NT 6.2; rv:15.0) Gecko/20100101 Firefox/15.0
SQL Query: SELECT * FROM users WHERE ua='Mozilla/5.0 (Windows NT 6.2; rv:15.0)
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/blind.png)

http://127.0.0.1:8080/littlesecrets-main/logs.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/blind1.png)

Aqui o parâmetro User-Agent está aceitando o input do browser. Normalmente, esse valor não pode ser modificado, mas podemos tentar mudar isso para ver o comportamento dele.

```
User-Agent: SQLI
SQL Query: SELECT * FROM users WHERE ua='SQLI'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/blind2.png)

http://127.0.0.1:8080/littlesecrets-main/logs.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/blind3.png)

Aqui o User-Agent foi modificado e a página retorna um valor válido

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/blind4.png)

```
User-Agent: SQLI'
SQL Query: SELECT * FROM users WHERE ua='SQLI''
```

Não há saida na página de log. Significa que o parâmetro User-Agent é vulnerável a code injection e o código que nós injetamos quebrou a query. O código tem que ser feito de uma maneira que não quebre a requisição SQL. O próximo passo agora é colocar uns comandos SQL pra verificar se realmente temos a vulnerabilidade.

```
User-Agent: SQLI' and 1='1
SQL Query: SELECT * FROM users WHERE ua='SQLI' AND 1='1'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/blind5.png)

Aqui a página deu retorno 0, isso foi por que temos uma saída verdadeira.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/blind6.png)

```
User-Agent: SQLI' and 1='2
SQL Query: SELECT * FROM users WHERE ua='SQLI' AND 1='2'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/blind7.png)

Aqui também mostrou uma mensagem, a query é falsa mas é possível, por isso foi mostrada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/blind8.png)

Agora vamos descobrir a quantidade de colunas que tem no banco de dados

```
User-Agent: SQLI' order by 1 -- +
SQL Query: SELECT * FROM users WHERE ua='SQLI' ORDER BY 1 -- +'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/blind9.png)

Não mostrou mensagem de erro no log, ou seja, não é uma query válida

Bom, SQLi Blind, é a mesma ideia do SQLi normal que estamos acostumados a fazer, mas temos que ir "adivinhando" caracter por caracter os dados, por isso leva um bom tempo pra ser feito, um bom blog que explica mais ou menos como funciona é esse: https://bentrobotlabs.wordpress.com/category/security/

Aqui pra ganhar tempo (e porque também não dei conta de fazer na mão) vou usar o `sqlmap` pra extrair os dados desse banco de dados. Mais tarde quando conseguir fazer isso melhor, eu faço aqui a injeção blind.

Demora muito tempo pra realizar essa extração, por ser blind ele é mais lento que o normal

```bash

```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/sqlmap.png)

Aqui ele encontrou a vulnerabilidade no `User-Agent`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/sqlmap1.png)

Por ser um TIME-BASED ele vai demorar um bom tempo para trazer os resultados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/sqlmap2.png)

Opa, achamos dois hashes e usuários, vamos fazer o brute force neles então pra ver se conseguimos adentrar a máquina

Verificamos como utilizar o john para essa quebra de senha

http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/john.png)

Realizamos a quebra dela

```bash
john --format=raw-md5 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/john1.png)

Beleza! Achamos uma senha

**3pinkysaf33pinkysaf3 (pinkymanage)**

Agora vamos tentar um SSH nessa máquina com esse usuário, uma vez que temos a porta 64666 aberta com o SSH, como foi vista na enumeração

# pinkymanage -> pinky

Entramos nela!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/ssh.png)

Olhando pelas pastas web, encontramos um diretório que não haviamos encontrado antes, o **/var/www/html/littlesecrets-main/ultrasecretadminf1l35**

Nele temos dois arquivos, um **note.txt** e um arquivo oculto **.ultrasecret**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/ssh1.png)

Quando verificamos do que se trata é uma chave ssh em base64

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/ssh2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/ssh3.png)

Agora verificamos quais usuários temos na máquina, possivelmente essa chave é do usuário **pinky**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/ssh4.png)

Passamos pra nossa máquina, e entramos como usuário **pinky** agora

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/ssh5.png)

# pinky -> root

Agora vamos iniciar a escalação de privilégio para o usuário root

Usamos o Linpeas para verificar vulnerabilidades na máquina para escalação de privilégio

https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/lin.png)

Baixamos na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/lin1.png)

Agora executamos na máquina virtual

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/lin2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/lin3.png)

Encontramos um arquivo com `suid` habilitado na home do meu usuário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/lin4.png)

Verificamos do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/lin5.png)

Não conseguimos ver muito o que ele faz, mas vemos que temos um `segmentation fault` nele, ou seja, possivelmente vai ser uma exploração de Buffer Overflow nesse aplicativo que está rodando com permissões de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/lin6.png)

Passamos esse arquivo para nossa máquina, pra podermos montar o exploit para ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/lin7.png)

Ali na pasta do usuário também temos um arquivo de anotação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/lin8.png)

**Been working on this program to help me when I need to do administrator tasks sudo is just too hard to configure and I can never remember my root password! Sadly I'm fairly new to C so I was working on my printing skills because Im not sure how to implement shell spawning yet :(**

Vamos fazer o buffer overflow nessa aplicação então

## Buffer Overflow

Vamos tentar explicar passo a passo como funciona essa exploração de buffer overflow em linux, a ideia é a mesma do windows, devemos encontrar o EIP, sobrescrever ele e assim ganhar acesso à áreas da memória que teoricamente não deveríamos ter acesso

1. Abrimos ele com o `gdb` mais especificamente o `gef`

```bash
gdb ./adminhelper
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/buf.png)

2. Verificar as proteções que esse binário tem, com o comando `checksec`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/buf1.png)

Obs: uma coisa pra se notar é que ele não está com o NX habilitado, ou seja, podemos executar shellcode diretamente na stack.

3. Devemos reproduzir o segmentation fault da aplicação, pra verificar o momento exato em que ele perde o controle da aplicação

Criaremos um `pattern` de 100 bytes

```bash
pattern create 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/buf2.png)

4. Rodamos esse pattern na aplicação, pra verificarmos o que estará no EIP no momento do crash

```bash
r 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/buf3.png)

O rbp apareceu com a string `jaaaaaaakaaaaaaalaaaaaaamaaa`

5. Descobrimos o momento exato do crash

```bash
pattern offset 'jaaaaaaakaaaaaaalaaaaaaamaaa'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/buf4.png)

6. Criamos o offset em python pra comprovarmos o crash

```bash
python -c "print 'A'*72"
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/buf5.png)

E comprovamos o crash

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-pinkyspalace1/buf6.png)

7. Jogamos o shellcode ali dentro dele, nesse espaço de memória pra ser executado

