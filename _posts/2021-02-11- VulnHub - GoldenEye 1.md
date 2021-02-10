---
title: "VulnHub - GoldenEye 1"
tags: [Linux, Easy]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/inicial.png)

Link: [GoldenEye1](https://www.vulnhub.com/entry/w34kn3ss-1,270/)

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

> Portas 25, 55006 e 55007 -> E-mail

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

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/sev4.png)

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

## Re-Re-Enumeração Porta 80 - severnaya-station.com - Doak user e Admin user

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

Logamos como admin então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/adm.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-goldeneye1/adm1.png)




