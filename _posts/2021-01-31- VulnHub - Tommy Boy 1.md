---
title: "VulnHub - Tommy Boy 1"
tags: [Linux, Easy, Gobuster, Wfuzz, BurpSuite, Hydra, Medusa, Sudo]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/inicial.png)

Link: [RickdiculouslyEasy](https://www.vulnhub.com/entry/rickdiculouslyeasy-1,207/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas aberta no servidor

> Porta 22 -> SSH

> Porta 80 -> Web

> Porta 8008 -> Web?!

## Enumeração da Porta 8008

Abrimos ela no navegador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/web.png)

Hummm... esse **sup3rl33t** pareceu ser dica de senha...

Rodamos o gobuster

```bash
gobuster dir -u http://192.168.56.116:8008 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 200
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/gobuster.png)

Nada...

## Enumeração da Porta 80

Acessamos ela no navegador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/web1.png)

Rodamos o gobuster

```bash
gobuster dir -u http://192.168.56.116 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 200
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/gobuster1.png)

Verificamos que todas as requisições são redirecionadas, então vamos usar o wfuzz

```bash
wfuzz -c --sc 200 -t 200 -w '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' -u 'http://192.168.56.116/FUZZ'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/wfuzz.png)

### robots.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/robots.png)

Vamos acessar as entradas do robots.txt

#### /flag-numero-uno.txt

Pegamos a primeira Flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/flag.png)

#### /6packsofb...soda/

Uma gif...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/soda.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/soda1.png)

Verificamos se tem algo escondido nela com o binwalk

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/soda2.png)

Realmente nada...

#### /lukeiamyourfather

Outra gif...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/luke.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/luke1.png)

Verificamos se tem algo escondido nela com o binwalk

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/luke2.png)

Nada...

#### /lookalivelowbridge

Outra gif...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/bri.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/bri1.png)

Verificamos se tem algo escondido nela com o binwalk

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/bri2.png)

Nada...

## Verificando Código Fonte

Sempre é bom verificar código fonte das páginas web... verificando a da porta 80, temos algo de interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/fon.png)

Então acessamo o vídeo que ele fala da dica onde está o blog escondido

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/youtube.png)

### /prehistoricforest

Acessamos ele então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/pre.png)

Pelo visto é um worpdress

Verificamos os posts dele

Achamos uma flag...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/f.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/f1.png)

Esse nos chamou atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/post.png)

Verificamos seus comentários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/post1.png)

Acessamos o /richard

### /richard

É uma foto...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/ric.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/ric1.png)

Binwalk nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/ric2.png)

Nada.... exif nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/exif.png)

Opa, apareceu um hash...

```
ce154b5a8e59c89732bc25d6a2e6b90b
```

Jogamos no google e apareceu **spanky**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/hash.png)

Acessamos aquele post que precisava de senha com essa senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/pass.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/pass1.png)