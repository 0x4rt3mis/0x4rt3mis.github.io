---
title: "VulnHub - Tommy Boy 1"
tags: [Linux, Medium, Wpscan, Gobuster, Wfuzz, Exiftool, Binwalk, FTP, Wfuzz User Agent, Wfuzz Brute Force, Crunch, Fcrackzip, Wordpress, Magic Number, Find]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/inicial.png)

Link: [Tommy Boy 1](https://www.vulnhub.com/entry/tommy-boy-1,157/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas aberta no servidor

> Porta 22 -> SSH

> Porta 80 -> Web

> Porta 8008 -> Web?!

## Enumeração da Porta 8008

Abrimos ela no navegador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/web.png)

Hummm... esse **sup3rl33t** pareceu ser dica de senha...

Rodamos o gobuster

```bash
gobuster dir -u http://192.168.56.116:8008 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 200
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/gobuster.png)

Nada...

## Enumeração da Porta 80

Acessamos ela no navegador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/web1.png)

Rodamos o gobuster

```bash
gobuster dir -u http://192.168.56.116 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 200
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/gobuster1.png)

Verificamos que todas as requisições são redirecionadas, então vamos usar o wfuzz

```bash
wfuzz -c --sc 200 -t 200 -w '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' -u 'http://192.168.56.116/FUZZ'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/wfuzz.png)

### robots.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/robots.png)

Vamos acessar as entradas do robots.txt

#### /flag-numero-uno.txt

Pegamos a primeira Flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/flag.png)

#### /6packsofb...soda/

Uma gif...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/soda.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/soda1.png)

Verificamos se tem algo escondido nela com o binwalk

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/soda2.png)

Realmente nada...

#### /lukeiamyourfather

Outra gif...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/luke.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/luke1.png)

Verificamos se tem algo escondido nela com o binwalk

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/luke2.png)

Nada...

#### /lookalivelowbridge

Outra gif...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/bri.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/bri1.png)

Verificamos se tem algo escondido nela com o binwalk

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/bri2.png)

Nada...

## Verificando Código Fonte

Sempre é bom verificar código fonte das páginas web... verificando a da porta 80, temos algo de interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/fon.png)

Então acessamo o vídeo que ele fala da dica onde está o blog escondido

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/youtube.png)

### /prehistoricforest

Acessamos ele então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/pre.png)

Pelo visto é um worpdress

Verificamos os posts dele

Achamos uma flag...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/f.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/f1.png)

Esse nos chamou atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/post.png)

Verificamos seus comentários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/post1.png)

Acessamos o /richard

### /richard

É uma foto...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/ric.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/ric1.png)

Binwalk nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/ric2.png)

Nada.... exif nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/exif.png)

Opa, apareceu um hash...

```
ce154b5a8e59c89732bc25d6a2e6b90b
```

Jogamos no google e apareceu **spanky**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/hash.png)

Acessamos aquele post que precisava de senha com essa senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/pass.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/pass1.png)

Bom aqui ta falando que tem um servidor FTP que abre e fecha... temos um login e ele fala que a senha é bem fraca...

Vamos fazer um nmap full port scan pra ver se encontramos algo

Primeiro não encontramos nada...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/full.png)

Então esperamos 15 minutos como está descrito no post...

E...

Ai está!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/ftp.png)

## Enumeração da Porta 65534

É um ftp... login e senha **nickburns** como está no post descrito

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/ftp1.png)

Baixamos o arquivo que está sendo fornecido ali e lemos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/ftp2.png)

## /NickIzL33t

Aqui fala que tem em algum lugar uma pasta **NickIzL33t**... primeira coisa que me veio na cabeça foi a porta 8008, então vamos lá

Aqui está!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/secret.png)

Hum... perdi um bom tempo aqui até pegar a sacada do Steve Jobs...

Trocamos o User Agent para um da Apple, e deu certo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/user.png)

Agora fazemos um brute force com o wfuzz, pra descobrir esse html que ele fala, coloquei uma wordlist pequena, mas essa palavra tem na **rockyou**

```bash
wfuzz -c --hw 32,14 -z file,wordlist.txt -H "User-Agent: Iphone" http://192.168.56.116:8008/NickIzL33t/FUZZ.html
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/wfuzz1.png)

Ai está... **fallon1.html**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/fallon.png)

Acessamos os arquivos

**hint.txt**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/hint.png)

**flagtres.txt**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/hint1.png)

**backup**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/hint2.png)

## Gerando Wordlists

Bom, será necessária a geração de wordlists para podermos quebrar a senha do backup... O que sabemos até agora?

```
Primeiras 3 letras são 'bev'
Quatro últimas são '1995'
bev******1995
```

### Crunch

Primeiro vamos demonstrar com o crunch a geração dessa senha, verificamos como usamos o crunch no man

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/crunch.png)

```bash
crunch 13 13 -t bev,%%@@^1995 -o tommy.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/crunch1.png)

### Python

Agora vamos demonstrar através de um script em python

gerar.py
```python
import string
import itertools

prefix = 'bev'
suffix = '1995'
uppercase = list(string.ascii_uppercase)
lowercase = list(string.ascii_lowercase)
numbers = list(string.digits)
symbols = list('$%^&*()-_+=|\<>[]{}#@/~')

part1 = uppercase
part2 = [''.join(s) for s in itertools.product(numbers, repeat=2)]
part3 = [''.join(s) for s in itertools.product(lowercase, repeat=2)]
part4 = symbols

candidates = reduce(lambda a,b: [i+j for i in a for j in b], [part1, part2, part3, part4])
for candidate in candidates:
  print prefix + candidate + suffix
```

Ai está

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/pyt.png)

## Fcrackzip

Agora com o **fcrackzip** fazemos a quebra da senha do arquivo zip

```bash
fcrackzip -v -D -u -p senhas.txt t0msp4ssw0rdz.zip
```

Senha quebrada!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/fcrack.png)

Dezipamos o arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/fcrack1.png)

Lemos o arquivo password.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/fcrack2.png)

Bom... aqui ele fala de usuários que tem acesso ao servidor... vamos verificar quais usuários ativos temos no wordpress

## Wordpress

```bash
wpscan  --url 192.168.56.116/prehistoricforest/ --enumerate u
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/wpscan.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/wpscan1.png)

Então agora vamos fazer o bruteforce desse usuário tom

### Wfuzz

Podemos fazer pelo wfuzz

```bash
wfuzz -c -z file,/usr/share/seclists/Passwords/darkweb2017-top10000.txt --hl 71 --hs incorrect -d "log=tom&pwd=FUZZ" http://192.168.56.116/prehistoricforest/wp-login.php
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/brute.png)

### Wpscan

Também pelo wpscan

```bash
wpscan --url http://192.168.56.116/prehistoricforest -P /usr/share/seclists/Passwords/darkweb2017-top10000.txt -U tom
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/brute1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/brute2.png)

# Reverse Shell

Bom, uma vez com uma senha, vamos tentar conseguis um shell nessa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/login.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/login1.png)

Olhando nos "Drafts" encontramos algo de interessante, onde ele menciona sobre o **passwords.txt** de antes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/login2.png)

Bom, sendo assim, logo já tentei um ssh com o usuário bigtommysenior e a senha fatguyinalittlecoat1938!!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/ssh.png)

Pegamos a quarta flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/flag2.png)

Verificamos na mensagem que a outra flag está em **/.5.txt** e realmente está lá, só que quem é o dono dela é o **www-data**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/ssh1.png)

Devemos pegar um reverse shell como www-data... verificando no wordpress não temos como modificar os plugins, pq não temos permissões para isso...

Verificamos pelo **find / -perm -2 -type d 2>/dev/null** as pastas que ele tem permissão

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/find.png)

Também podemos verificar no **apache2** verificamos uma "pasta secreta" dele

**cat /etc/apache2/sites-enabled/2.conf**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/apache.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/apache1.png)

Acessamos via navegador, lembrar de manter o User Agent como Iphone...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/apach2.png)

Copiamos nosso php-reverse-shell, modificamos o IP e a Porta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/reverse.png)

Upamos no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/reverse2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/reverse3.png)

Certo, temos que mudar o magic number dele

Verificamos no arquivo .htaccess que os arquivos .gif serão interpretados como php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/reverse1.png)

## Mudando o Magic Number

Colocamos **GIF89a** na primeira linha do arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/magic.png)

Assim não deu certo...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/magic1.png)

Bom, ele tem filtros bacanas ali... mas o que podemos fazer é jogar uma imagem msm, (na verdade um shell, só que .gif) e mudar dentro da pasta para .php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/mv.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/mv1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/mv2.png)

Show... agora alteramos ele dentro da pasta para .php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/mv3.png)

## www-data

Agora recebemos o reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/mv4.png)

Pegamos a quinta flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/flag3.png)

## LOOT.zip

A senha pra desbloqueio vai ser

**B34rcl4wsZ4l1nskyTinyHeadEditButtonButtcrack**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-tommyboy1/flag4.png)

Fechamos!
