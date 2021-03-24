---
title: "Hack The Box - DevOops"
tags: [Linux,Medium,Gobuster,PayloadAllTheThings]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/140>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas

> Porta 22 -> SSH

> Portas 5000 -> Servidor Web

## Enumeração da porta 5000

Abrindo a página verificamos o que tem nela

Verificamos a página muito estranha, que é literalmente uma foto de um feed

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_web.png)

## Gobuster

Executamos o gobuster para procurar por diretórios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_gobuster.png)

> gobuster dir -u http://10.10.10.91:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50

Explicação parâmetros

> dir --> Diretórios

> -u --> URL

> -w --> Wordlist utilizada

> -x --> Vai procurar por arquivos com extensão .php também

> -t --> Aumento o número de threads para ir mais rápido

### /feed

Entramos no diretório /feed para ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_feed.png)

Bom, aqui não vamos conseguir nada de útil, então prosseguimos

### /upload

Entramos no diretório /upload para ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_upload.png)

Interessante, ai mostra um campo para upar arquivos XML... vamos tentar explorar isso

# Explorando XML

Primeira coisa a se fazer e mandar para o *BurpSuite* tendo em vista facilicar o processo de exploração

## BurpSuite

Criamos um XML bem simples, sem muita informação, somente para teste

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_xml.png)

Upamos no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_burp.png)

Enviamos para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_burp1.png)

Enviamos para o Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_burp2.png)


### Enviando Requisição XML

Agora, alteramos a requisição pra ser exatamente como o site pede para ser enviada...

No /upload ele pede para ter os itens *Author, Subject e Content*

```
<payload>
  <Author>Quero Shell</Author>
  <Subject>Agora</Subject>
  <Content>Devoops</Content>
</payload> 
```

Enviamos e vemos que deu certo, o servidor recebeu a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_burp3.png)

## Explorando a requisição

Uma vez que encontramos o ponto que podemos explorar nessa máquina, iremos pesquisar por maneiras de exploração XXE

Uma alternativa muito boa, que deve sempre ser levada em conta é o `PayloadAllTheThings`, um repositório show de bola no GitHub, onde tem diversas ferramentas, códigos para utilizar durantes seus pentests/CTFs

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_p.png)

> https://github.com/swisskyrepo/PayloadsAllTheThings

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_p1.png)

Também temos esse blog onde ele aborda bastante sobre XXE Exploitation

> https://depthsecurity.com/blog/exploitation-xml-external-entity-xxe-injection

### Classic XXE

Pesquisando dentro desse repositório encontramos esse código que podemos utilizar

> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/Files/Classic%20XXE%20-%20etc%20passwd.xml

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_p2.png)

```
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

Adaptamos ele no nosso BurpSuite para enviar a requisição e vizualizar o /etc/passwd

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_burp4.png)

Bom, uma vez que conseguimos acessar o /etc/passwd, conseguimos ver os usuários que possuem shell válido na máquina e consequentemente podemos ver se eles tem chaves ssh em suas pastas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_roosa.png)

Passamos a chave ssh da roosa para nossa Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_roosa1.png)

### Conexão SSH Estabelecida

Estabelecemos uma conexão SSH com a máquina com o usuário roosa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_ssh.png)

# Escalação de Privilégio

Agora iniciamos a escalação de privilégio dessa máquina

Não iremos rodar nenhum script pq não vai dar muito resultado

Verificamos que a máquina possui o usuário `git` então possivelmente há repositorios do github nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_git.png)

Pesquisamos por diretórios .git

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_git1.png)

Entramos no diretório encontrado

> ./work/blogfeed/.git

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_git2.png)

Verificamos o log dos commits realizados pela máquina

> git log

Encontramos um que nos chamou atenção, o `d387abf63e05c9628a59195cec9311751bdb283f` onde fala que ele enviou acidentalmente uma chave para o servidor e está revertendo isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_git3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_git4.png)

Interessante... vamos verificar do que se trata ela

> git diff d387abf63e05c9628a59195cec9311751bdb283f

Para nossa surpresa, conseguimos outra chave SSH!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_git5.png)

Salvamos a chave na nossa Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_git6.png)

Logamos como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_git7.png)

## Pegamos a flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_root.png)


# Adicionais

A máquina já está feita. Não foi difícil, mas vamos explorar outros pontos nela agora.

Este blog traz bastante coisa sobre Gits desconfigurados e como extrair dados disso

> https://blog.netspi.com/dumping-git-data-from-misconfigured-web-servers/

## Obs 1 - 'git log -p'

Com o comando `git log -p` iriamos ver commit por commit, para poder achar a chave SSH, pq as vezes ela não pode estar tão na cara assim falando que enviou acidentalmente uma chave para o servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-devoops/D_obs.png)

## Obs 2 - Explorar o Python Pickles

Há outro modo de se explorar o shell de usuário através do pickles que o feed.py usa, mas pessalmente passou da minha capacidade intelectual fazer isso. Se alguém conseguir e estiver disposto a me ajudar, ficarei grato.

O vídeo onde 'explica' o que deve ser feito é:

Nem com o vídeo eu entendi! Fica pra próxima, quando eu tiver mais condições de entendimento

> https://www.youtube.com/watch?v=tQ34Ntkr7H4

