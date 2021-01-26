---
title: "VulnHub - Symfonos 5"
tags: [Linux, Medium, LDAP, LFI, RFI, BurpSuite, BurpSuite Repeater, DPKG, GTFobins, Sudo, FPM, Docker, Gobuster]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/inicial.png)

Link: <https://www.vulnhub.com/entry/symfonos-52,415/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 4 portas abertas no servidor

> Porta 22 -> Servidor SSH

> Porta 80 -> Servidor Web

> Portas 389 e 636 -> LDAP

## Enumeração da Porta 80 (Web)

Entramos no site pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/web.png)

Rodamos o gobuster nele

```bash
gobuster dir -u http://192.168.56.109 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/gobuster.png)

Acessamos o que ele encontrou, **portraits.php**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/portraits.png)

Acessamos o **admin.php** e vemos que é um campo de login e senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/admin.png)

### Descoberta do RFI

Testei de tudo... aspas, SQLI... nada deu certo, então coloquei a senha e usuário com \* e deu certo!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/admin1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/admin2.png)

Agora verificando no código fonte do **home.php** uma coisa nos chamou atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/admin3.png)

**href="home.php?url=http://127.0.0.1/portraits.php"**

Pelo que parece ele esta chamando um arquivo externo...

E realmente está, mas não conseguimos executar códigos me php nem nada disso através desse RFI, talvez seja um rabbit hole, então vamos prosseguir

### Descoberta do LFI

Pensando nisso joguei a requisição para o burpsuite e para minha surpresa conseguimos ver que também temos um lfi nessa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/admin4.png)

Procurando por arquivos de interesse na máquinas, sempre é bom lermos o código fonte do site que está sendo executado, e quando acessamos o **admin.php** vemos que temos credenciais do **ldap** nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/admin5.png)

Show, vamos prosseguir agora na exploração da máquina

## Enumeração LDAP

```bash
nmap 192.168.56.109 -p 389 --script ldap-search --script-args 'ldap.username="cn=admin,dc=symfonos,dc=local", ldap.password="qMDdyZh3cT6eeAWD"'
```

Vemos que conseguimos enumerar tranquilo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/ldap.png)

Pelo que parece conseguimos um usuário chamado **zeus**, se lembrarmos lá em cima quando enumeramos o /etc/passwd esse era um usuário válido

Também podemos enumerar através do `ldapsearch`

```bash
ldapsearch -D "cn=admin,dc=symfonos,dc=local" -w qMDdyZh3cT6eeAWD -p 389 -h 192.168.56.109 -b "dc=symfonos,dc=local"
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/ldap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/ldap2.png)

zeus:cetkKf4wCuHC9FET

# Zeus -> Root

Agora com um shell de zeus através do ssh vamos iniciar a escalação de privlégios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/ldap3.png)

Com o **sudo -l** verificamos que podemos rodar o **dpkg** como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/ldap4.png)

Verificamos no [GTFobins](https://gtfobins.github.io/gtfobins/dpkg/) como podemos explorar isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/sudo.png)

Então vamos lá

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/sudo1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/sudo2.png)

## Flag

Pegamos a flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/flag.png)

# Algo a Mais

Podemos escalar privilégio de outro modo, compilando nosso pacote .deb e enviando pra máquina

## FPM

[Referência](https://lsdsecurity.com/2019/01/linux-privilege-escalation-using-apt-get-apt-dpkg-to-abuse-sudo-nopasswd-misconfiguration/)

Para isso vamos utilizar o utilitário chamado [FPM](https://github.com/jordansissel/fpm)

Baixamos ele para nossa máquina

```bash
apt-get install ruby ruby-dev rubygems build-essential
gem install --no-document fpm
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/install.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/install1.png)

Criamos nosso arquivo **shell.sh** e fazemos o arquivo .deb com o comando

```bash
fpm -s dir -t deb -n exploit --before-install shell.sh /root/VulnHub/Symfonos5/
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/install2.png)

Passamos ele para a máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/install3.png)

Agora viramos root!

```bash
sudo dpkg -i exploit_1.0_amd64.deb
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/install4.png)

## Por que o RFI não funcionou?

Estranho ele não ter funcionado, mas consegui verificar isso ao procurar pela pasta do site web e não encontrar no sistema o /var/www/html... então quando pesquisei pelo **find . -name admin.php** vi que ele está em um **container** do docker...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/container.png)

Com o comando **docker images** conseguimos ver todos os containers que temos instalados no sistema

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/docker.png)

Acessamos o container e vemos que ele está fora do IP da nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos5/container1.png)

Não conseguimos acesso até nossa máquina através dele, por isso não conseguimos um reverse shell