---
title: "VulnHub - Bob 1"
tags: [Linux, Easy, GPG, Robots, Gobuster, Sudo]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/inicial.png)

Link: [Bob1](https://www.vulnhub.com/entry/bob-101,226/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/nmap.png)

Nmap full ports

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/nmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/nmap2.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 2 portas aberta no servidor

> Porta 80 -> Web

> Porta 25468 -> SSH

## Enumeração da Porta 80

Primeiro acessamos ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/web.png)

Rodamos o gobuster

```bash
gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/gobuster.png)

### /robots.txt

Verificamos o que temos no robots.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/robots.png)

```
User-agent: *
Disallow: /login.php
Disallow: /dev_shell.php
Disallow: /lat_memo.html
Disallow: /passwords.html
```

### /passwords.html

Apenas verificamos do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/pass.png)

### /lat_memo.html

Apenas verificamos do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/lat.png)

### /dev_shell.php

Bom, esse nome nos chamou atenção...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/dev.png)

Sério? Fácil assim? Não pode ser...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/dev1.png)

Sim... estamos dentro...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/dev2.png)

# www-data -> Bob

Vasculhando a máquina encontramos diversas coisas interessantes, uma delas dentro da home do bob um arquivo com senhas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/bob.png)

```
jc:Qwerty
seb:T1tanium_Pa$$word_Hack3rs_Fear_M3
```

Os dois derão certo...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/bob1.png)

Encontramos também a senha da elliot

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/bob2.png)

```
elliot:theadminisdumb
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/bob3.png)

Também deu certo!

## Bob Home's

Vasculhando o diretório do Bob encontramos algumas coisas interessantes

Esse login.txt.gpg nos chamou atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/bob4.png)

Vasculhando as páginas encontramos mais algo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/bob5.png)

Lembra dele ele todo tempo comentar sobre arquivos escondidos e tudo mais... bem agora achei bem CTF mesmo essa parte, mas fazer oq...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/bob6.png)

A senha é:

```
HARPOCRATES
```

Mas senha do que? Daquele arquivo login.txt.gpg

```bash
gpg --batch --passphrase HARPOCRATES -d login.txt.gpg
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/bob7.png)

Não conseguimos como o usuário www-data, tentamos com outro então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/bob8.png)

Show, outra senha...

```
bob:b0bcat_
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/bob9.png)

# Bob -> Root

Bom aqui ficou fácil, ele tem sudo na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/sudo.png)

Viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/sudo1.png)

Pegamos a flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-bob1/flag.png)

# Algo a Mais

Vamos verificar se conseguimor ver mais alguma coisa nessa máquina

Verificamos aquele dev_shell.php pra ver como ele é feito

dev_shell.php
```
<html>
<body>
  <?php
    //init
    $invalid = 0;
    $command = ($_POST['in_command']);
    $bad_words = array("pwd", "ls", "netcat", "ssh", "wget", "ping", "traceroute", "cat", "nc");
  ?>
  <style>
    #back{
      position: fixed;
      top: 0;
      left: 0;
      min-width: 100%;
      min-height: 100%;
      z-index:-10
    }
      #shell{
        color: white;
        text-align: center;
    }
  </style>
  <!-- WIP, don't forget to report any bugs we don't want another breach guys
  -Bob -->
  <div id="shell">
    <h2>
      dev_shell
    </h2>
    <form action="dev_shell.php" method="post">
      Command: <input type="text" name="in_command" /> <br>
      <input type="submit" value="submit">
    </form>
    <br>
    <h5>Output:</h5>
    <?php
    system("running command...");
      //executes system Command
      //checks for sneaky ;
      if (strpos($command, ';') !==false){
        system("echo Nice try skid, but you will never get through this bulletproof php code"); //doesn't work :P
      }
      else{
        $is_he_a_bad_man = explode(' ', trim($command));
        //checks for dangerous commands
        if (in_array($is_he_a_bad_man[0], $bad_words)){
          system("echo Get out skid lol");
        }
        else{
          system($_POST['in_command']);
        }
      }
    ?>
  </div>
    <img src="dev_shell_back.png" id="back" alt="">
</body>
</html>
```

Verificamos que ele é simples, não tendo muita coisa a se explicar, tem umas bad words que vai dar erro caso sejam digitadas mas nada de complexo...