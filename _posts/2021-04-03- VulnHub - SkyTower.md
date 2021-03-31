---
title: "VulnHub - SkyTower"
tags: [Linux,Easy,Web,Gobuster,BurSuite,SQLInjection]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/inicial.png)

Link: [SkyTower](https://www.vulnhub.com/entry/skytower-1,96/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 3 portas abertas no servidor

> Porta 22 -> SSH

> Portas 80 e 3128 -> Web

## Enumeração da Porta 80

Acessamos a página web para verificar do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/web.png)

Gobuster nela

```bash
gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/gobuster.png)

Copiamos as duas imagens que tem nos diretórios e tentamos ver se tem algo nelas com o `binwalk` e o `exiftool`, mas não encontramos nada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/back.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/back1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/exif.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/exif1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/bin.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/bin1.png)

Testamos SQLInjection no campo do login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/sql2.png)

Opa! Encontramos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/sql1.png)

Mandamos a requisição para o BurpSuite para melhor trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/burp2.png)

Agora começamos a verificar qual Payload vamos utilizar para bypassar esse campo de login e senha

Uma boa referência é esse site

https://www.exploit-db.com/papers/17934

Dentro dos payloads encontramos um pra bypassar

```
user'|| 1=1 #
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/burp3.png)

User: john
Password: hereisjohn

Pronto, temos um login e senha! Mas se analisarmos a porta ssh está filtrada, vamos fazer isso de vários modos.

# SSH Proxychains

Bom, vendo que temos a porta 3128 aberta com um proxy, podemos utilizar ele para pivotear pra a máquina

Adicionamos o proxy no /etc/proxychains

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/proxy.png)

Agora acessamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/proxy1.png)

Vemos que da um erro quando acessamos, ele fecha o shell, então encontramos uma maneira de bypassar isso

Adicionando o /bin/bash no final do comando é o suficiente

```bash
proxychains ssh john@192.168.56.101 /bin/bash
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/proxy2.png)

# Proxytunnel

Podemos fazer esse pivoting pelo `proxytunnel` também

```bash
proxytunnel -p 192.168.56.101:3128 -d 127.0.0.1:22 -a 2222
netstat -antp tcp | grep :2222
ssh john@127.0.0.1 -p 2222 /bin/bash
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/proxy3.png)

Beleza, vamos para mais um

# SOCAT

```bash
socat TCP-LISTEN:9999,reuseaddr,fork PROXY:192.168.56.101:127.0.0.1:22,proxyport=3128
ssh john@127.0.0.1 -p 9999
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/proxy4.png)

# john -> root

Agora vamos tentar fazer a escalação de privilégio desse usuário, a primeira coisa que nos embarrera é o fato de não conseguirmos fazer o upgrade do bash

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/proxy5.png)

Verificamos então o .bashrc

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/proxy6.png)

Vemos que ele embarrera a gente conseguir fazer o upgrade do shell, então renomeamos ele para a sessão sair da influencia dele

E conseguimos fazer o upgrade dele normal, temos um shell melhor agora pra trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/prox7.png)

Ao verificarmos o `/var/www/login.php` vemos que ele tem a senha do mysql

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-skytower/sql.png)

