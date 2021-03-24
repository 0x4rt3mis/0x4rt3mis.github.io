---
title: "Hack The Box - Swagshop"
tags: [Linux,Easy,Web]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/188>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 -> Servidor SSH, dificilmente a exploração vai ser por aqui

> Porta 80 -> Servidor Web.

## Enumeração da porta 80

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_web.png)

# Exploração

## Procuramos por exploits para `Magento`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_exp.png)

### Encontramos esse

> https://www.exploit-db.com/exploits/37977

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_exp1.png)

### Colocamos ele para funcionar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_exp3.png)

> Criou o login forme:forme

#### Testamos e vemos que realmente criou o login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_log.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_log1.png)

## Nesta máquina após logar, consigo vizualisar dois tipos de ataque para conseguir RCE

# 1º Ataque --> Upando um PHP Shell como se fosse JPG

O nome desse ataque é Froghopper, econtrei como explorar neste link:

> https://www.foregenix.com/blog/anatomy-of-a-magento-attack-froghopper

#### Primeiro passo, devo ativar `Allow Symlinks`

> System - Configuration - Developer - Template Settings

Isso tendo em vista conseguirmos acessar o Newsletter Templates fora do diretório raiz do servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_frog.png)

#### Segundo passo é criarmos nosso PHP Shell em forma de jpg

Usarei os disponíveis na própria Kali

> cp /usr/share/webshells/php/php-reverse-shell.php .

Fazemos as alterações necessárias

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_frog0.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_frog1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_frog2.png)

#### Terceiro passo é upar essa "foto" dentro do site

> Catalog -> Manage Categories -> New Root Category

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_frog3.png)

#### Acessamos a pasta onde foi salvo

> media/catalog/category

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_frog4.png)

Ainda não está pronto

O ultimo passo é forçar o Magento a ler isso, mesmo estando fora da pasta raiz do servidor, em um Template que eu criei

Acessamos a aba para adicionar um novo template

> Newsletter -> Newsletter Template -> Add New template 

Magento carrega templates de "app/design/frontend/base/default/frontend/base/default/template/" por default, então, eu adicionei "../../../../../../" ao começo do path para ir até meu webshell.

> {{block type='core/template' template='../../../../../../media/catalog/category/foto.jpg'}}

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_frog5.png)

#### Clicamos em "Preview Template" e magicamente ganhamos um shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_frog6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_frog7.png)

Show de bola. Agora vamos fazer do outro modo

# 2º Ataque --> Upando um PHP mesmo

#### Primeiro passo eu vou até "Catalog -> Manage Products"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_p.png)

#### Escolhemos qualquer um dos itens expostos (No caso eu selecionei 5 x Hack The Box Sticker)

#### Clicamos em "Custom Option -> Add New Option" e adicionamos um novo produto que aceita arquivos .php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_p1.png)

#### Adicionamos nosso php no servidor através da página de vendas do site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_p2.png)

#### Clicamos em "Add to Cart" e o arquivo .php será upado para o servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_p3.png)

#### Ele é upado para `http://10.10.10.140/media/custom_options/quote/f/o/`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_p4.png)

#### Executamos e ganhamos a shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_p6.png)

## Escalação de Privilégio

Agora vamos escalar privilégio para root

### Com `sudo -l` verificamos que podemos rodar comandos de Vi na pasta especificada como se root fosse

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_r.png)

> sudo /usr/bin/vi /var/www/html/tmpfile -c ':sh'

#### Executamos e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_r1.png)

### Pegamos a flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-swagshop/Swagshop_user.png)