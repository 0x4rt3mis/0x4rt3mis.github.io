---
title: "VulnHub - Silky-CTF: 0x02"
tags: [Linux,Medium,Buffer Overflow Linux,BurpSuite]
categories: VulnHub OSWE
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/inicial.png)

Link: [Silky-CTF: 0x02](https://www.vulnhub.com/entry/silky-ctf-0x02,307/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 2 portas aberta no servidor

> Porta 80 -> Web

> Porta 22 -> SSH

## Enumeração da Porta 80

Entramos na página web pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/web.png)

Gobuster

```bash
gobuster dir -u http://192.168.56.128/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/gobuster.png)

### admin.php

Entramos no admin.php pra ver o que podemos fazer

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/admin.png)

Verificamos que é um campo de Login e Senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/admin1.png)

Tentamos colocar qualquer coisa pra ver como se sai

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/admin2.png)

Deu erro, mas o que chamou atenção foi que ele recebeu como parâmetro GET a senha e usuário, isso é um pouco incomum.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/admin.png)

### BurpSuite

Então jogamos a requisição pro BurpSuite pra ver como podemos trabalhar com ela melhor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/burp2.png)

Após alguns testes, verificamos que no parâmetro USER conseguimos um RCE...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/burp3.png)

## Reverse Shell

Agora é só pegar um reverse shell nessa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/rev.png)

Agora vamos iniciar a escalação de privilégios

# www-data --> Root

Primeiro passo é rodar o linpeas

Baixamos ele para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/lin.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/lin1.png)

Jogamos na máquina alvo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/lin2.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/lin3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/lin4.png)

Encontramos um binário com permissões de SUID... interessante, ele não é nativo da máquina, então o ponto de escalação de privilégio possivelmente é por ai

Verificamos o que ele faz

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/lin5.png)

Pelo que parece ele é o conteúdo do /etc/shadow, mas não temos essa senha... então possivelmente pode ser que tenhamos que fazer um buffer overflow nessa aplicação

## Buffer Overflow

Exfiltramos ele para nossa Kali, para melhor trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/buf.png)

Verificamos se encontramos alguma coisa de interessante nas strings dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/buf2.png)

O que chamou atenção foi *strcpy* que é vulnerável a buffer overflow... então tentamos mandar uma string pra ele pra ver o que podemos verificar

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/buf3.png)

Enviamos esse pattern para a aplicação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/buf4.png)

Ele não deu Segmentation Fault, mas o que chamou atenção foi que aparece um endereço Hex ali...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/buf4.png)

**0x63413163 != 0x496c5962**

Possivelmente nosso offset, então vemos o tamanho dele

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 63413163
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/buf5.png)

O pattern é 64, sabendo disso e que tem um =! entre os valores, então mandamos o pattern mais o deveria ser igual

```bash
./cat_shadow $(python -c 'print "A"*64 + "\x62\x59\x6c\x49"')
```

Ai está! Conseguimos printar o shadow

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/buf6.png)

Agora pegamos o shadow e o passwd da máquina alvo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/buf7.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/buf8.png)

Unshadow para ficar em um formato pro john entender

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/buf9.png)

John para quebrar as senhas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/buf10.png)

Descobrimos a senha `greygrey`

# Flags

Viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/root.png)

Pegamos as flags

Root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/root1.png)

User

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-silky/root2.png)
