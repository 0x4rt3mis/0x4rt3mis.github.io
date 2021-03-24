---
title: "Hack The Box - Networked"
tags: [Linux,Easy,Nohup,RFI,Webshell,Sudo]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Networked_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/203>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor e 1 fechada (Provável Firewall bloqueando)

> Porta 22 -> Servidor SSH, dificilmente a exploração vai ser por aqui

> Porta 80 e 443 -> Servidor Web

## Enumeração da porta 80

Abrindo a página verificamos o que tem nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_web.png)

Como de costume, sempre é bom termos rodando algum tipo de enumeração enquanto verificamos outras portas e serviços, pensando nisso vou deixar rodando um `Wfuzz` na porta 80 pra descobrir diretórios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_wfuzz.png)

Explicação Wfuzz:
> -c --> Exibir com cores

> -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --> indicamos que o método será dicionário e o arquivo especificado

> --hc 404 --> Não vai exibir os arquivos que deram erro 404.

> -t 200 --> Quantidade de threads (pra ir mais rápido)

### Verificando o código fonte da página encontramos algo interessante `upload e gallery`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_fonte.png)

Verificamos o que tem no `uploads`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_up.png)

Verificamos o que tem no `gallery`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_gal.png)

Interessante, uploads nos deu apenas um "." na página

Verificamos agora o `backup` que o wfuzz achou

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_backeup.png)

### Baixamos o arquivo para nossa máquina e dezipamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_back.png)

### Verificaremos agora com o comando `grep -Ri '$_' *` quais são os locais em que o usuário executa algo em todos os arquivos que foram extraidos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_grep.png)

Verificamos que está sendo realizado upload de fotos, olhando mais a fundo do upload.php verificamos que ele possue a função *check_file_type*
Mais a baixo verificamos quais são os tipos de arquivos que ele aceita, que é: *png, jpg, gif, jpeg*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_up1.png)

Bom, com essas informações já conseguimos realizar o upload de uma foto como os magic number modificados, contudo quero ver comprovar esse check que ele faz através dos magic numbers, verificando dentro do lib.php também há a função check_file_type. Ele verifica através do $mime_type que é uma função php pra verificar os magic numbers do arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_lib.png)

# Exploração

### Agora, sabendo disso tudo vamos iniciar a exploração dessa falha, podemos fazer de dois jeitos aqui, o primeiro é mais detalhado usando o BurpSuite e gerando um shell reverso, o outro mais direto apenas upando um WebShell com magic number de php, na tentativa e erro

Primeiro passo é criar um arquivo .php com magic number de gif

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_dif.png)

Comprovando que realmente o servidor interpretará isso como sendo .php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_dif1.png)

Abrimos o upload.php na página e mandamos a requisição para o burp quando tentamos upar o *dificil.php*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_dif2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_dif3.png)

Mandamos para o burp e para o repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_dif4.png)

Verificamos que deu um erro de *Invalid image file*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_dif5.png)

Identificamos onde está esse erro no upload.php pra podermos sanar, verificamos que ele está fazendo um check com a extensão do arquivo e com o nome

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_dif8.png)

Então mudamos a extensão no burp para .php mesmo, retirando o GIF89A também da erro, mas agora se olharmos o erro é *Invalid image file.* com o "." no final, então vamos no upload.php pra verificar onde está esse erro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_dif7.png)

Agora comprovamos que realmente ele verifica o conteúdo (magic number) mas também verifica o nome, ou seja, tem que ter nome de imagem, então satisfazemos essas duas exigências e conseguimos upar nosso arquivo php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_dif9.png)

Agora vamos para a galeria (photos.php)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_dif10.png)

Executamos nosso "shell"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_dif11.png)

## Pegamos um reverse shell

Jogamos para o burp o "shell" pra melhor trabalhar

Primeiro devemos mudar uma configuração do burp, pra ele poder capturar requisições de imagens (uma vez que oq nós upamos no servidor para todos efeitos é uma imagem)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_shell.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_shell3.png)

Mandamos pro repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_shell1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_shell4.png)

Pegamos um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_shell5.png)

# Escalação de Privilégio

### Olhando dentro do home verificamos um arquivo que chamou a atenção, é o `check_attack.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_check.png)

> nohup /bin/rm -f $path$value > /dev/null 2>&1 &

Nohup
> Os processos no Unix serão terminados quando você fizer logout do sistema ou quando sair do shell atual, não importando se eles estiverem rodando em foreground ou em background. Eles recebem o sinal HUP (hangup), que é um aviso do terminal a seus processos dependentes de que ocorreu um logout. A única forma de assegurar que um processo que esteja rodando atualmente não seja terminado quando sairmos é usando o comando nohup.

### Então, percebendo que podemos manipular o nome do arquivo a ser executado podemos colocar ; e o comando a ser executado, sendo assim executamos um shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_nohup.png)

#### Com o usuário guly, verificamos as permissões de sudo -l

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_sudo.png)

#### Verificamos o script e o que podemos fazer com ele para virar root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_sudo1.png)

Verificamos o que ele faz, e vemos que espaços são permitidos (na regex). Então se dermos qualquer coisa seguido de espaço e algum comando, teremos RCE como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_sudo2.png)

### Pegamos a flag de root e user

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-networked/Net_rot.png)
