---
title: "VulnHub - Temple Of Doom"
tags: [Linux,Easy]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/inicial.png)

Link: [Temple Of Doom](https://www.vulnhub.com/entry/linsecurity-1,244/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 -> SSH

> Porta 666 -> Web

## Enumeração da Porta 666

Acessamos a página web para verificar do que se trata, parece uma animação interativa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/web.png)

No código fonte não encontramos nada de mais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-tepleofdoom/web1.png)

Gobuster nela

```bash
gobuster dir -u http://192.168.56.150:666 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/gobuster.png)

Não encontramos nada na página... interessante, quando reiniciamos ela, atualizamos a página somos remetidos a outra página de erro que aparece

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/web2.png)

Apareceu um erro relativo ao JSON não estar sendo serializado corretamente... vamos mandar ela pro burp pra ver se conseguimos extrair algo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/burp1.png)

Mandamos pro Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/burp2.png)

Algo que chamou atenção foi o Cookie passado, é um base64

```
eyJ1c2VybmFtZSI6IkFkbWluIiwiY3NyZnRva2VuIjoidTMydDRvM3RiM2dnNDMxZnMzNGdnZGdjaGp3bnphMGw9IiwiRXhwaXJlcz0iOkZyaWRheSwgMTMgT2N0IDIwMTggMDA6MDA6MDAgR01UIn0=
```

Fazemos a desencodação dele e temos:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/burp3.png)

```
{"username":"Admin","csrftoken":"u32t4o3tb3gg431fs34ggdgchjwnza0l=","Expires=":Friday, 13 Oct 2018 00:00:00 GMT"}
```

O que temos de errado ai? A sintaxe ta incorreta, está faltando uma aspas antes de Friday... e isso quebra a requisição

```
{"username":"Admin","csrftoken":"u32t4o3tb3gg431fs34ggdgchjwnza0l=","Expires=":"Friday, 13 Oct 2018 00:00:00 GMT"}
```

Encodamos o certo e enviamos novamente a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/burp4.png)

Opa! Hello Admin!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-templeofdoom/burp5.png)

Bom isso pode parecer inútil, mas nos da a dica de uma falha na função `unserialize()`