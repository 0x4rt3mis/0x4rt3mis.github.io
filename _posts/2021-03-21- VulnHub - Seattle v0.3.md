---
title: "VulnHub - Seattle v0.3"
tags: [Linux, Medium]
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

> Porta 22 -> SSH

```
Essa máquina vamos fazer de um modo diferente, ela tem várias vulnerabilidades já pré-configuradas pra gente treinara s habilidades em web, vou tentar demonstrar cada uma delas
```

As vulnerabilidades que serão exploradas serão:

1. SQL Injection
2. Blind SQL Injection

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